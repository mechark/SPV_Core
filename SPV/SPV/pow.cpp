#include <iostream>
#include <vector>
#include <string>
#include <math.h>

#include "SHA256.h"
#include "spv.h"

namespace header_chain
{
	boost::multiprecision::int1024_t compute_target(string bits)
	{
		tcp::converter conv;

		int mantissa = conv.hex_str_toi(bits.substr(0, 2));
		boost::multiprecision::int1024_t exponent = conv.hex_str_toeln(bits.substr(2, 6));
		
		boost::multiprecision::int1024_t target = exponent * (boost::multiprecision::int1024_t(pow(256, mantissa - 3)));
		return target;
	}

	bool POW::proof_of_work(std::vector<models::header> headers)
	{
		bool is_correct = false;

		tcp::converter conv;
		std::stringstream sstream;

		for (int i = 0; i < headers.size() - 1; ++i)
		{
			// Header hash
			string header_hash;
			for (char ch : headers[i + 1].prev_block) header_hash += ch;

			boost::multiprecision::int1024_t hash = conv.hex_str_toeln(conv.hex_str_to_little_endian(header_hash));
			boost::multiprecision::int1024_t target = compute_target(headers[i].hex_bits);

			string shash = hash.str();
			string thash = target.str();
			if (hash < target) is_correct = true;
			else
			{
				cout << "error has thrown at pow::proof_of_work() method.blocks header was incorrect";
				terminate();
			}
		}

		return is_correct;
	}
}