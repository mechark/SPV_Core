#include <iostream>
#include <chrono>
#include <vector>
#include <sstream>
#include <boost/dynamic_bitset.hpp>
#include <cstdarg>
#include <random>

#include "sha256.h"
#include "spv.h"

using namespace std::chrono;

namespace tcp
{
	std::string message::version_message_payload(string _ip, bool is_debug)
	{
		stringstream sstream;
		converter conv;

		// Payload fields definition

		// Version - 4 bytes
		int32_t version = 70016;
		sstream << hex << _byteswap_ulong(version);

		// Service - 8 bytes
		string service = "0100000000000000";
		sstream << service;

		// Timestamp - 8 bytes
		int64_t timestamp = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
		sstream << hex << _byteswap_uint64(timestamp);

		// Addr_recv - 26 bytes
		sstream << "0000000000000000";
		string ip_prefix = "00000000000000000000FFFF";
		sstream << ip_prefix;
			
		// replace ip
		string ip = _ip;
		vector<string> ip_res;
		conv.ip2hex(ip, ip_res);
		for (string s : ip_res) sstream << hex << stoi(s);
		int32_t port = 8333;
		sstream << hex << port;

		// Addr_from
			
		//service and from_ip
		sstream << service;
		sstream << "000000000000000000000000";
		sstream << "00000000";
		sstream << "0000";

		// Nonce
		std::random_device rd;
		std::mt19937_64 n64(rd());

		uint64_t nonce = n64();
		sstream << hex << _byteswap_uint64(nonce);

		// User-agent
		sstream << "00";

		// Block height
		sstream << hex << "00000000";

		// Relay
		bool relay = 0;
		sstream << hex << "00";

		if (is_debug)
		{
			cout << "Message Payload:" << endl;
			cout << "Version: " << hex << _byteswap_ulong(version) << endl;
			cout << "Service: " << service << endl;
			cout << "Timestamp: " << hex << timestamp << endl;
			cout << "Addr_recv: " << hex << service << ip_prefix << " ";
			for (string s : ip_res) cout << hex << stoi(s) << " ";
			cout << hex << port << endl;
			cout << "Addr_from: " << service <<
				ip_prefix;
			//for (string s : from_ip_res) cout << hex << stoi(s);
			cout << hex << port << endl;
			cout << "Nonce: " << hex << _byteswap_uint64(nonce) << endl;
			cout << "User Agent: " << "3B2EB35D8CE61765" << endl;
			//cout << "Start Height: " << hex << _byteswap_ulong(start_height) << endl;
			cout << "Relay: " << "00" << endl;
			cout << endl;
		}

		return sstream.str();
	}

	std::string message::ping_message_payload()
	{
		std::stringstream sstream;

		std::random_device rd;
		std::mt19937_64 n64(rd());

		uint64_t nonce = n64();
		sstream << hex << _byteswap_uint64(nonce);

		return sstream.str();
	}

	std::string message::getheaders_message_payload(string block_hash)
	{
		string genesis_block = block_hash;
		stringstream sstream;
		converter conv;

		// Version
		uint32_t version = 70016;
		sstream << hex << _byteswap_ulong(version);

		// Hash count
		uint8_t hash_count = 1;
		sstream << "01";

		// Block locator hashes
		sstream << conv.hex_str_to_little_endian(genesis_block);

		// Hash stop. Not stopping by default
		sstream << "0000000000000000000000000000000000000000000000000000000000000000";

		return sstream.str();
	}

	std::string message::verack_message()
	{
		string verack;
		
		// Magic
		string magic = "F9BEB4D9";
		verack += magic;

		// Verack command
		verack += "76657261636B000000000000";

		// Payload long
		verack += "00000000";

		// Checksum
		verack += "5DF6E0E2";

		return verack;
	}

	std::string message::make_message(std::string payload, std::string command)
	{
		stringstream sstream;
		converter conv;

		// Magic
		string magic = "F9BEB4D9";
		sstream << magic;

		// Command
		for (char ch : command) sstream << hex << int(ch);
		while (sstream.str().length() != 32) sstream << "0";

		// Length of payload
		uint32_t length = payload.length() / 2;
		sstream << hex << _byteswap_ulong(length);

		// Checksum
		string checksum;
		conv.checksum(payload, checksum);
		sstream << hex << checksum;

		return sstream.str() + payload;
	}

	std::string message::make_ping_message(std::string payload)
	{
		stringstream sstream;
		converter conv;

		// Magic
		string magic = "F9BEB4D9";
		sstream << magic;

		// Command
		sstream << "70696e670000000000000000";

		// Length of payload
		sstream << "08000000";

		// Checksum
		string checksum;
		conv.checksum(payload, checksum);
		sstream << hex << checksum;

		return sstream.str() + payload;
	}
}