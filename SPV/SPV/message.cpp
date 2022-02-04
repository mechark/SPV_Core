#include <iostream>
#include <chrono>
#include <vector>
#include <sstream>
#include <cstdarg>
#include <random>
#include <bitset>
#include <cmath>
#include <boost/dynamic_bitset.hpp>

#include "MurmurHash3.h"
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
		sstream << hex << "01";

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

	uint32_t message::bloom_hash(const char* data, const uint32_t nFilterBytes, const uint32_t nHashNum, uint32_t nTweak)
	{
		uint32_t seed = (nHashNum * 0xfba4c795 + nTweak);
		uint32_t hash_otpt[1];

		MurmurHash3_x86_32(data, strlen(data), seed, hash_otpt);
		return hash_otpt[0] % (nFilterBytes * 8);
	}

	string message::filterload_message_payload(const char* data_to_hash, unsigned int N)
	{
		stringstream sstream;
		stringstream filter_stream;
		converter conv;

		std::random_device rd;
		std::mt19937 n32(rd());

		// Max sizes of bloom filter
		const uint32_t bytes_max = 36000;
		const uint32_t funcs_max = 50;
		
		// User keys number
		const double fp_rate = 0.00001;

		// Values to send

		// Number of bytes in bloom filter
		uint32_t bytes_formula = round((-1 / pow(log(2), 2) * N * log(fp_rate)) / 8);
		uint32_t nFilterBytes = min(bytes_formula, bytes_max);

		// Filter
		boost::dynamic_bitset<> filter(nFilterBytes * 8);

		// Number of hash functions in bloom filter
		const uint32_t nHashFuncs = int(min(round(nFilterBytes * 8 / N * log(2)), double(funcs_max)));

		// Random seed to add to the seed value
		uint32_t nTweak = n32();

		// Flags to choose replying mode
		uint8_t nFlags = 2;

		for (size_t nHashNum = 0; nHashNum < nHashFuncs; ++nHashNum)
		{
			uint32_t filter_index = bloom_hash(data_to_hash, nFilterBytes, nHashNum, nTweak);
			filter[filter_index] = true;
		}

		string setted_filter = conv.bytes_to_hex(filter);
		// Filter bytes
		sstream << hex << conv.uito_little_endian_str(filter.size() / 8, 1);

		sstream << hex << setted_filter;
		sstream << hex << conv.uito_little_endian_str(nHashFuncs);
		sstream << hex << _byteswap_ulong(nTweak);
		sstream << hex << conv.uito_little_endian_str(nFlags, 1);

		string res = sstream.str();

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
		//sstream << hex << _byteswap_ulong(length);
		sstream << hex << conv.uito_little_endian_str(length);

		// Checksum
		string checksum;
		conv.checksum(payload, checksum);
		sstream << hex << checksum;

		if (sstream.str().size() % 2 != 0) sstream << "0";
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