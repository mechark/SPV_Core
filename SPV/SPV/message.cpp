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
	std::string message::version_message_payload(int _start_height, string _ip, bool is_debug)
	{
		stringstream sstream;
		converter conv;

		// Payload fields definition

		// Version - 4 bytes
		int32_t version = 70016;
		sstream << hex << _byteswap_ulong(version);

		// Service - 8 bytes
		//string service = "0100000000000000";
		string service = "0000000000000000";
		sstream << service;

		// Timestamp - 8 bytes
		int64_t timestamp = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
		sstream << hex << _byteswap_uint64(timestamp);

		// Addr_recv - 26 bytes
		sstream << service;
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

		// port

		/*ip = "215.239.156.213";
		vector<string> from_ip_res;
		conv.ip2hex(ip, from_ip_res);
		for (string s : from_ip_res) sstream << hex << stoi(s);
		sstream << port;*/

		// Nonce
		std::random_device rd;
		std::mt19937_64 n64(rd());

		uint64_t nonce = n64();
		sstream << hex << _byteswap_uint64(nonce);

		// User-agent
		//sstream << "102f5361746f7368693a302e32312e302f";
		sstream << "00";

		// Block height
		int32_t start_height = _start_height;
		//sstream << hex << _byteswap_ulong(start_height);
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
			cout << "Start Height: " << hex << _byteswap_ulong(start_height) << endl;
			cout << "Relay: " << "00" << endl;
			cout << endl;
		}
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
		//sstream << "76657273696F6E0000000000";
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

	std::string message::ping_message_payload()
	{
		std::stringstream sstream;

		std::random_device rd;
		std::mt19937_64 n64(rd());

		uint64_t nonce = n64();
		sstream << hex << _byteswap_uint64(nonce);

		return sstream.str();
	}

	std::string message::getheaders_message_payload(int hashes_count, char block_locator_hashes[65])
	{
		string genesis_block = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
		stringstream sstream;

		// Version
		uint32_t version = 70016;
		sstream << hex << _byteswap_ulong(version);

		// Hash count
		uint8_t hash_count = hashes_count;
		sstream << hex << hash_count;

		// Block locator hashes
		if (hashes_count > 1)
			sstream << block_locator_hashes;
		else
			sstream << "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

		// Hash stop. Not stopping by default
		sstream << "0000000000000000000000000000000000000000000000000000000000000000";

		return sstream.str();
	}
}