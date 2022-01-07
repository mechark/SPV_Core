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
	void console_log(vector<models::header> headers)
	{
		for (int i = 0; i < headers.size(); ++i)
		{
			std::ofstream fs("D:\/console_log.txt");
			fs << "Version: ";
			fs << headers[i].block_version << "\n";
		}
	}

	void buffer::serialize(const string file, vector<models::header> headers)
	{
		
		std::ofstream fs(file, std::ofstream::binary);
		boost::archive::binary_oarchive oar(fs, boost::archive::no_header);

		oar << headers;
	}

	vector<models::header> buffer::deserialize(const string file)
	{
		std::ifstream fs(file, std::ofstream::binary);
		boost::archive::binary_iarchive iar(fs, boost::archive::no_header);

		vector<models::header> headers;
		iar >> headers;

		return headers;
	}
}