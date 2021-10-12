#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <boost/dynamic_bitset.hpp>
#include "SHA256.h"
#include "spv.h"

namespace tcp
{
	void converter::ip2hex(string ip, vector<string>& ip_res)
	{
		string sub;
		while (ip.length() != 0)
		{
			int pos = ip.find(".");
			sub = ip.substr(0, pos);
			ip_res.push_back(sub);

			if (pos != -1)
				ip.replace(0, pos + 1, "");
			else if (pos == -1)
				ip.replace(0, ip.length(), "");
		}
	}

	void converter::checksum(string payload_str, string& checksum)
	{
		string payload_bytes_str = hex_str_to_binary(payload_str);
		vector<unsigned char> payload_bytes;

		// Double hashing
		picosha2::hash256(payload_bytes_str.begin(), payload_bytes_str.end(), payload_bytes.begin(), payload_bytes.end());
		string hex_hash = picosha2::hash256_hex_string(payload_bytes_str);
		payload_bytes_str = hex_str_to_binary(hex_hash);
		picosha2::hash256(payload_bytes_str.begin(), payload_bytes_str.end(), payload_bytes.begin(), payload_bytes.end());
		hex_hash = picosha2::hash256_hex_string(payload_bytes_str);

		checksum = hex_hash.substr(0, 8);
	}

	int converter::hex_str_toi(string hex_str, bool is_little_endian)
	{
		unsigned int res = 0;

		std::stringstream sstream;

		if (is_little_endian)
			hex_str = hex_str_to_little_endian(hex_str);

		sstream << std::hex << hex_str;
		sstream >> res;

		return res;
	}

	string converter::hex_str_to_binary(string hex_str)
	{
		std::string binary_str, extract_str;

		try
		{
			cout << hex_str << endl;
			if (hex_str.size() % 2 != 0) return "";
			binary_str.reserve(hex_str.length() / 2);
			for (std::string::const_iterator pos = hex_str.begin(); pos < hex_str.end(); pos += 2)
			{
				extract_str.assign(pos, pos + 2);
				binary_str.push_back(std::stoi(extract_str, nullptr, 16));
			}
		}
		catch (const std::exception& e)
		{
			std::cerr << "e.what() = " << e.what();
			throw - 1;
		}

		return binary_str;
	}

	string converter::hex_str_to_little_endian(string hex_str)
	{
		string les;

		try
		{
			if (hex_str.length() % 2 != 0) throw exception("String does not even");
			for (int i = hex_str.length() - 1; i < hex_str.length(); --i)
			{
				if (i % 2 == 0)
				{
					les += hex_str[i];
					les += hex_str[i + 1];
				}
			}
		}
		catch (exception ex)
		{
			throw exception("exception has thrown in hex_str_to_little_endian method");
		}

		return les;
	}
}