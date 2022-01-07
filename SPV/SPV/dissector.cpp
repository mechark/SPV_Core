#include <iostream>
#include <vector>
#include <string>

#include "spv.h"

namespace header_chain
{
	std::vector<models::header> 
	dissector::dissect(std::string& raw_headers, std::string& last_header_hash, string& hex_bits, const int header_length)
	{
		tcp::converter conv;
		if (raw_headers.size() > 0)
		{
			int headers_number = conv.hex_str_toi(raw_headers.substr(0, 4), true);
			raw_headers.replace(0, 4, "");
			std::vector<models::header> headers(headers_number);

			if ((raw_headers.size() % header_length) == 0)
			{
				for (int i = 0; i < headers_number; ++i)
				{
					// To get a raw hex header bytes make raw_headers.substr(0, 162)
					//string hdr_bytes = raw_headers.substr(0, 162);

					// Version
					string _version = raw_headers.substr(0, 8);
					int version = conv.hex_str_toi(_version, true);
					headers[i].block_version = static_cast<int32_t>(version);

					// Prev block hash
					string prev_blk_hash = raw_headers.substr(8, 64);
					for (int j = 0; j < 64; ++j)
					{
						(headers[i].prev_block[j]) = prev_blk_hash[j];
						(headers[i].prev_block[j]) = prev_blk_hash[j + 1];
					}

					// Merkle root hash
					string mrkl_root_hash = raw_headers.substr(72, 64);
					for (int j = 0; j < 64; ++j) 
					{
						(headers[i].prev_block[j]) = mrkl_root_hash[j];
						(headers[i].prev_block[j]) = mrkl_root_hash[j + 1];
					}

					// Timestamp
					string _timestamp = raw_headers.substr(136, 8);
					int timestamp = conv.hex_str_toi(_timestamp);
					headers[i].timestamp = static_cast<uint32_t>(timestamp);

					// Bits (difficulty target)
					string _difficulty = conv.hex_str_to_little_endian(raw_headers.substr(144, 8));
					unsigned long long bits = conv.hex_str_toi(_difficulty);
					headers[i].bits = static_cast<uint32_t>(bits);

					// Hex bits
					hex_bits = _difficulty;

					// Nonce
					string _nonce = raw_headers.substr(152, 8);
					int nonce = conv.hex_str_toi(_nonce);
					headers[i].nonce = static_cast<uint32_t>(nonce);

					raw_headers.replace(0, 162, "");
				}
			}
			for (char ch : headers[headers.size() - 1].prev_block) 
				last_header_hash += ch;

			return headers;
		}
		else
		{
			cout << "error in header_chain::dissector::dissect method.Incorrect number of headers bytes.";
			terminate();
		}
	}
}