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
			string getheaders(int curr_block_height);
		private:
			static vector<string> dns_seeds;
			void get_ips(vector<string>& dns_ips_out);
	};

	class message
	{
		public:
			string make_message(string payload, string command_name);
			string make_ping_message(string payload);
			string verack_message();
			string ping_message_payload();
			string getheaders_message_payload(int hashes_count, char block_locator_hashes[65] = {});
			string version_message_payload(int _start_height, string ip, bool is_debug);
		private:
	};

	class converter
	{
		public:
			void checksum(string payload_bytes, string& checksum);
			string hex_str_to_binary(string hex_str);
			string hex_str_to_little_endian(string hex_str);
			void ip2hex(string ip, vector<string>& ip_res);
	};
}