#include <iostream>
#include <string>
#include <vector>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <fstream>

#include "spv.h"

namespace repo
{
	std::uintmax_t file_size(const string file)
	{
		std::ifstream is(file);
		is.seekg(0, ios::end);
		uintmax_t size = is.tellg();
		return size;
	}

	void buffer::serialize(const string file, vector<models::header> headers)
	{
		const int headers_number = headers.size();
		if (headers_number == 0) terminate();

		std::ofstream fs(file, std::ofstream::binary);
		boost::archive::binary_oarchive oar(fs, boost::archive::no_header);

		for (int i = 0; i < headers_number; ++i)
		{
			oar << headers[i].block_version;
			oar << headers[i].prev_block;
			oar << headers[i].merkle_root;
			oar << headers[i].timestamp;
			oar << headers[i].bits;
			oar << headers[i].nonce;
		}
	}

	vector<models::header> buffer::deserialize(const string file)
	{
		const int one_header_bytes = 88;
		const int headers_number = file_size(file) / one_header_bytes;

		std::ifstream fs(file, std::ofstream::binary);
		boost::archive::binary_iarchive iar(fs, boost::archive::no_header);
		vector<models::header> headers(headers_number);

		for (int i = 0; i < headers_number; ++i)
		{
			iar >> headers[i].block_version;
			iar >> headers[i].prev_block;
			iar >> headers[i].merkle_root;
			iar >> headers[i].timestamp;
			iar >> headers[i].bits;
			iar >> headers[i].nonce;
		}

		return headers;
		
	}
}