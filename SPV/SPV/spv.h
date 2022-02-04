#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/serialization/access.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/asio.hpp>

using namespace std;
using namespace boost::asio;

#define DLL_EXPORT __declspec(dllexport)

extern "C"
{
	namespace tcp
	{
		class tcp_client
		{
			public:
				DLL_EXPORT tcp_client(vector<string> _dns_seeds);
				DLL_EXPORT string getheaders(string start_block_header);
				DLL_EXPORT void setfilter(const char* data_to_hash);
			private:
				DLL_EXPORT static vector<string> dns_seeds;
				DLL_EXPORT void get_ips(vector<string>& dns_ips_out);
				DLL_EXPORT int grab_payload_length(string message_header, int& headers_starts_at);
		};

		class message
		{
			public:
				DLL_EXPORT string make_message(string payload, string command_name);
				DLL_EXPORT string make_ping_message(string payload);
				DLL_EXPORT string verack_message();
				DLL_EXPORT string ping_message_payload();
				DLL_EXPORT string getheaders_message_payload(string block_hash);
				DLL_EXPORT uint32_t bloom_hash(const char* data, const uint32_t nFilterBytes, const uint32_t nHashNum, uint32_t nTweak);
				DLL_EXPORT string filterload_message_payload(const char* data_to_hash, unsigned int N);
				DLL_EXPORT string filteradd_message_payload();
				DLL_EXPORT string version_message_payload(string ip, bool is_debug);
		};

		class converter
		{
			public:
				DLL_EXPORT void checksum(string payload_bytes, string& checksum);
				DLL_EXPORT int hex_str_toi(string hex_str, bool is_little_endian = false);
				DLL_EXPORT boost::multiprecision::int1024_t hex_str_toeln(string hex_str, bool is_little_endian = false);
				DLL_EXPORT string hex_str_to_binary(string hex_str);
				DLL_EXPORT string bytes_to_hex(boost::dynamic_bitset<> bitset);
				DLL_EXPORT string hex_str_tosha256(string hex_str);
				DLL_EXPORT string uito_little_endian_str(unsigned long long n, int bytes_n = 4, bool is_little_endian = true);
				DLL_EXPORT string ito_little_endian_str(long long n, int bytes_n = 4, bool is_little_endian = true);
				DLL_EXPORT string hex_str_to_little_endian(string hex_str);
				DLL_EXPORT void ip2hex(string ip, vector<string>& ip_res);

			private:
				DLL_EXPORT bool is_even(string hex);
				DLL_EXPORT void bitset_reverse(boost::dynamic_bitset<>& bs);
		};
	}

	namespace models
	{
		struct header
		{
			public:
				int32_t block_version;
				char prev_block[32];
				char merkle_root[32];
				uint32_t timestamp;
				uint32_t bits;
				uint32_t nonce;
		};
	}

	namespace repo
	{
		class buffer
		{
			public:
				DLL_EXPORT void serialize(const string file, vector<models::header> headers);
				DLL_EXPORT vector<models::header> deserialize(const string file);
		};
	}

	namespace header_chain
	{
		class POW
		{
			public:
				DLL_EXPORT bool proof_of_work(vector<models::header> headers, string hex_bits);
		};

		class dissector
		{
			public:
				DLL_EXPORT vector<models::header> dissect(string& raw_headers, string& last_header_hash_out, string& hex_bits_out, const int header_length = 81);
		};
	}
}
