#pragma once

#include <cstdint>

#pragma pack(push, 1)
struct tcphdr_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t off_flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
};
#pragma pack(pop)
