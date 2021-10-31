#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <boost/dynamic_bitset.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/asio.hpp>

using namespace std;
using namespace boost::asio;

namespace tcp
{
	class tcp_client
	{
		public:
			__declspec(dllexport) tcp_client(vector<string> _dns_seeds);
			__declspec(dllexport) string getheaders(string start_block_header);
		private:
			__declspec(dllexport) static vector<string> dns_seeds;
			__declspec(dllexport) void get_ips(vector<string>& dns_ips_out);
			__declspec(dllexport) int grab_payload_length(string message_header, int& headers_starts_at);
	};

	class message
	{
		public:
			__declspec(dllexport) string make_message(string payload, string command_name);
			__declspec(dllexport) string make_ping_message(string payload);
			__declspec(dllexport) string verack_message();
			__declspec(dllexport) string ping_message_payload();
			__declspec(dllexport) string getheaders_message_payload(string block_hash);
			__declspec(dllexport) string version_message_payload(string ip, bool is_debug);
		private:
	};

	class converter
	{
		public:
			__declspec(dllexport) void checksum(string payload_bytes, string& checksum);
			__declspec(dllexport) int hex_str_toi(string hex_str, bool is_little_endian = false);
			__declspec(dllexport) boost::multiprecision::int1024_t hex_str_toeln(string hex_str, bool is_little_endian = false);
			__declspec(dllexport) string hex_str_to_binary(string hex_str);
			__declspec(dllexport) string hex_str_tosha256(string hex_str);
			__declspec(dllexport) string hex_str_to_little_endian(string hex_str);
			__declspec(dllexport) void ip2hex(string ip, vector<string>& ip_res);
	};
}

namespace models
{
	struct header
	{
		int32_t version;
		std::vector<char> prev_block;
		std::vector<char> merkle_root;
		uint32_t timestamp;
		uint32_t bits;
		string hex_bits;
		uint32_t nonce;

		string header_bytes;
	};
}

namespace header_chain
{
	class POW
	{
		public:
			__declspec(dllexport) bool proof_of_work(std::vector<models::header> headers);
	};

	class dissector
	{
		public:
			__declspec(dllexport) std::vector<models::header> dissect(std::string& raw_headers, std::string& last_header_hash, const int header_length = 81);
	};
}

