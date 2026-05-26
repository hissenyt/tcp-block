#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <algorithm>
#include <vector>

#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "ethhdr.h"
#include "ip.h"
#include "mac.h"
#include "tcphdr.h"

using namespace std;

static const int ETHER_HDR_LEN = 14;
static const int IP_HDR_LEN = 20;
static const int TCP_HDR_LEN = 20;

static const uint16_t ETH_TYPE_IP = 0x0800;
static const uint8_t IP_PROTO_TCP = 6;

static const uint16_t TCP_FLAG_FIN = 0x001;
static const uint16_t TCP_FLAG_RST = 0x004;
static const uint16_t TCP_FLAG_ACK = 0x010;

static const char redirect_msg[] =
    "HTTP/1.0 302 Redirect\r\n"
    "Location: http://warning.or.kr\r\n"
    "\r\n";

struct PseudoHeader final {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute__((packed));

static void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

static uint16_t checksum(const void* data, int len) {
    const uint16_t* p = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    if (len == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(p);
        sum += last;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

static uint16_t tcp_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    const uint8_t* tcp_packet,
    int tcp_len
) {
    PseudoHeader pseudo{};
    pseudo.src_ip = src_ip;
    pseudo.dst_ip = dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);

    vector<uint8_t> buf(sizeof(PseudoHeader) + tcp_len);
    memcpy(buf.data(), &pseudo, sizeof(PseudoHeader));
    memcpy(buf.data() + sizeof(PseudoHeader), tcp_packet, tcp_len);

    return checksum(buf.data(), static_cast<int>(buf.size()));
}

static bool contains_pattern(const uint8_t* data, int data_len, const string& pattern) {
    if (data == nullptr || data_len <= 0 || pattern.empty()) return false;

    const uint8_t* begin = data;
    const uint8_t* end = data + data_len;

    auto it = search(
        begin,
        end,
        pattern.begin(),
        pattern.end(),
        [](uint8_t a, char b) {
            return a == static_cast<uint8_t>(b);
        }
    );

    return it != end;
}

static void make_ipv4_header(
    uint8_t* ip,
    uint16_t total_len,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t id
) {
    memset(ip, 0, IP_HDR_LEN);

    ip[0] = 0x45;                  // IPv4, IHL = 5
    ip[1] = 0x00;                  // TOS
    *reinterpret_cast<uint16_t*>(ip + 2) = htons(total_len);
    *reinterpret_cast<uint16_t*>(ip + 4) = htons(id);
    *reinterpret_cast<uint16_t*>(ip + 6) = htons(0x4000); // Don't Fragment
    ip[8] = 64;                    // TTL
    ip[9] = IP_PROTO_TCP;
    *reinterpret_cast<uint32_t*>(ip + 12) = src_ip;
    *reinterpret_cast<uint32_t*>(ip + 16) = dst_ip;

    *reinterpret_cast<uint16_t*>(ip + 10) = 0;
    *reinterpret_cast<uint16_t*>(ip + 10) = checksum(ip, IP_HDR_LEN);
}

static void make_tcp_header(
    uint8_t* tcp,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq,
    uint32_t ack,
    uint16_t flags,
    uint16_t window
) {
    memset(tcp, 0, TCP_HDR_LEN);

    tcphdr_t* th = reinterpret_cast<tcphdr_t*>(tcp);

    th->src_port = src_port;
    th->dst_port = dst_port;
    th->seq_num = htonl(seq);
    th->ack_num = htonl(ack);
    th->off_flags = htons((5 << 12) | flags);
    th->window = htons(window);
    th->checksum = 0;
    th->urg_ptr = 0;
}

static bool parse_packet(
    const uint8_t* packet,
    int packet_len,
    const uint8_t** eth,
    const uint8_t** ip,
    const tcphdr_t** tcp,
    const uint8_t** tcp_data,
    int* ip_hl,
    int* tcp_hl,
    int* tcp_data_len
) {
    if (packet_len < ETHER_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN) return false;

    *eth = packet;

    uint16_t eth_type = ntohs(*reinterpret_cast<const uint16_t*>(packet + 12));
    if (eth_type != ETH_TYPE_IP) return false;

    *ip = packet + ETHER_HDR_LEN;

    uint8_t version = ((*ip)[0] >> 4) & 0x0f;
    if (version != 4) return false;

    *ip_hl = ((*ip)[0] & 0x0f) * 4;
    if (*ip_hl < IP_HDR_LEN) return false;

    uint16_t ip_total_len = ntohs(*reinterpret_cast<const uint16_t*>((*ip) + 2));
    if (ip_total_len < *ip_hl + TCP_HDR_LEN) return false;
    if (packet_len < ETHER_HDR_LEN + ip_total_len) return false;

    uint8_t protocol = (*ip)[9];
    if (protocol != IP_PROTO_TCP) return false;

    const uint8_t* tcp_ptr = (*ip) + *ip_hl;
    *tcp = reinterpret_cast<const tcphdr_t*>(tcp_ptr);

    uint16_t off_flags = ntohs((*tcp)->off_flags);
    *tcp_hl = ((off_flags >> 12) & 0x0f) * 4;
    if (*tcp_hl < TCP_HDR_LEN) return false;

    if (ip_total_len < *ip_hl + *tcp_hl) return false;

    *tcp_data = tcp_ptr + *tcp_hl;
    *tcp_data_len = ip_total_len - *ip_hl - *tcp_hl;

    return true;
}

static void send_forward_rst(
    pcap_t* handle,
    const uint8_t* eth,
    const uint8_t* ip,
    const tcphdr_t* tcp,
    int tcp_data_len
) {
    uint32_t src_ip = *reinterpret_cast<const uint32_t*>(ip + 12);
    uint32_t dst_ip = *reinterpret_cast<const uint32_t*>(ip + 16);

    uint16_t src_port = tcp->src_port;
    uint16_t dst_port = tcp->dst_port;

    uint32_t seq = ntohl(tcp->seq_num) + tcp_data_len;
    uint32_t ack = ntohl(tcp->ack_num);

    uint16_t ip_id = ntohs(*reinterpret_cast<const uint16_t*>(ip + 4));
    uint16_t window = ntohs(tcp->window);

    uint8_t packet[ETHER_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN];
    memset(packet, 0, sizeof(packet));

    /*
     * Forward direction:
     * client -> server 방향 RST.
     *
     * Ethernet은 원래 client -> gateway/server로 나가던 프레임의
     * MAC 방향을 그대로 사용한다.
     */
    memcpy(packet, eth, ETHER_HDR_LEN);

    uint8_t* new_ip = packet + ETHER_HDR_LEN;
    uint8_t* new_tcp = new_ip + IP_HDR_LEN;

    make_ipv4_header(
        new_ip,
        IP_HDR_LEN + TCP_HDR_LEN,
        src_ip,
        dst_ip,
        ip_id + 1
    );

    make_tcp_header(
        new_tcp,
        src_port,
        dst_port,
        seq,
        ack,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        window
    );

    reinterpret_cast<tcphdr_t*>(new_tcp)->checksum =
        tcp_checksum(src_ip, dst_ip, new_tcp, TCP_HDR_LEN);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "pcap_sendpacket forward RST failed: %s\n", pcap_geterr(handle));
    } else {
        printf("[+] forward RST sent\n");
    }
}

static void send_backward_fin_redirect(
    int raw_sock,
    const uint8_t* ip,
    const tcphdr_t* tcp,
    int tcp_data_len
) {
    uint32_t client_ip = *reinterpret_cast<const uint32_t*>(ip + 12);
    uint32_t server_ip = *reinterpret_cast<const uint32_t*>(ip + 16);

    uint16_t client_port = tcp->src_port;
    uint16_t server_port = tcp->dst_port;

    uint32_t seq = ntohl(tcp->ack_num);
    uint32_t ack = ntohl(tcp->seq_num) + tcp_data_len;

    uint16_t ip_id = ntohs(*reinterpret_cast<const uint16_t*>(ip + 4));
    uint16_t window = ntohs(tcp->window);

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(redirect_msg);
    int payload_len = static_cast<int>(strlen(redirect_msg));

    int tcp_len = TCP_HDR_LEN + payload_len;
    int ip_len = IP_HDR_LEN + tcp_len;

    vector<uint8_t> packet(ip_len);
    memset(packet.data(), 0, packet.size());

    uint8_t* new_ip = packet.data();
    uint8_t* new_tcp = new_ip + IP_HDR_LEN;
    uint8_t* new_data = new_tcp + TCP_HDR_LEN;

    /*
     * Backward direction:
     * server -> client 방향 FIN + ACK + 302 Redirect.
     */
    make_ipv4_header(
        new_ip,
        ip_len,
        server_ip,
        client_ip,
        ip_id + 2
    );

    make_tcp_header(
        new_tcp,
        server_port,
        client_port,
        seq,
        ack,
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        window
    );

    memcpy(new_data, payload, payload_len);

    reinterpret_cast<tcphdr_t*>(new_tcp)->checksum =
        tcp_checksum(server_ip, client_ip, new_tcp, tcp_len);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = client_ip;

    ssize_t sent = sendto(
        raw_sock,
        packet.data(),
        packet.size(),
        0,
        reinterpret_cast<sockaddr*>(&addr),
        sizeof(addr)
    );

    if (sent < 0) {
        perror("sendto backward FIN/302 failed");
    } else {
        printf("[+] backward FIN/302 sent\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];
    string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        dev,
        BUFSIZ,
        1,
        1,
        errbuf
    );

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Only Ethernet is supported.\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    /*
     * TCP 패킷만 캡처한다.
     * HTTP Host 기반 테스트라면 port 80 조건을 추가해도 되지만,
     * 과제 명세는 TCP Data에서 pattern 검색이므로 tcp 전체로 둔다.
     */
    bpf_program fp{};
    if (pcap_compile(handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(raw_sock);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("[*] tcp-block started\n");
    printf("[*] interface : %s\n", dev);
    printf("[*] pattern   : %s\n", pattern.c_str());

    while (true) {
        pcap_pkthdr* header;
        const uint8_t* packet;

        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
            break;
        }

        const uint8_t* eth = nullptr;
        const uint8_t* ip = nullptr;
        const tcphdr_t* tcp = nullptr;
        const uint8_t* tcp_data = nullptr;

        int ip_hl = 0;
        int tcp_hl = 0;
        int tcp_data_len = 0;

        if (!parse_packet(
                packet,
                header->caplen,
                &eth,
                &ip,
                &tcp,
                &tcp_data,
                &ip_hl,
                &tcp_hl,
                &tcp_data_len
            )) {
            continue;
        }

        if (tcp_data_len <= 0) continue;

        if (!contains_pattern(tcp_data, tcp_data_len, pattern)) continue;

        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, ip + 12, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, ip + 16, dst_ip_str, sizeof(dst_ip_str));

        printf("\n[!] pattern matched\n");
        printf("    %s:%u -> %s:%u\n",
               src_ip_str,
               ntohs(tcp->src_port),
               dst_ip_str,
               ntohs(tcp->dst_port));
        printf("    tcp data len: %d\n", tcp_data_len);

        send_forward_rst(
            handle,
            eth,
            ip,
            tcp,
            tcp_data_len
        );

        send_backward_fin_redirect(
            raw_sock,
            ip,
            tcp,
            tcp_data_len
        );
    }

    close(raw_sock);
    pcap_close(handle);

    return EXIT_SUCCESS;
}
