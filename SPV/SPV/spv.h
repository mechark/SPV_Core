#include <iostream>
#include <string>
#include <vector>
#include <boost/dynamic_bitset.hpp>
#include <boost/asio.hpp>
#pragma once

using namespace std;
using namespace boost::asio;

namespace tcp
{
	class tcp_client
	{
		public:
			tcp_client(vector<string> _dns_seeds);
			string getheaders(string start_block_header);
		private:
			static vector<string> dns_seeds;
			void get_ips(vector<string>& dns_ips_out);
			int grab_payload_length(string message_header, int& headers_starts_at);
	};

	class message
	{
		public:
			string make_message(string payload, string command_name);
			string make_ping_message(string payload);
			string verack_message();
			string ping_message_payload();
			string getheaders_message_payload(string block_hash);
			string version_message_payload(string ip, bool is_debug);
		private:
	};

	class converter
	{
		public:
			void checksum(string payload_bytes, string& checksum);
			int hex_str_toi(string hex_str, bool is_little_endian = false);
			string hex_str_to_binary(string hex_str);
			string hex_str_to_little_endian(string hex_str);
			void ip2hex(string ip, vector<string>& ip_res);
	};
}

namespace models
{
	class header
	{
	public:
		int32_t version;
		std::vector<char> prev_block;
		std::vector<char> merkle_root;
		uint32_t timestamp;
		uint32_t bits;
		uint32_t nonce;
	};
}

namespace header_chain
{
	class pow
	{
		public:
			bool proof_of_work(std::vector<models::header> headers);
	};

	class dissector
	{
		public:
			std::vector<models::header> dissect(std::string& raw_headers, const int header_length = 81);
	};
}

