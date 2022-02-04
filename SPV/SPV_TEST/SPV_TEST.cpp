#include <iostream>
#include <vector>
#include <string>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/algorithm/hex.hpp>
#include <stdio.h>
#include <sstream>
#include <bitset>
#include <random>

#include "spv.h"

using namespace std;
using namespace boost::asio;

vector<string> dns_seeds
{
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
	"seed.bitcoin.sprovoost.nl",
	"dnsseed.emzy.de",
	"seed.bitcoin.wiz.biz"
};

vector<string> dns_seed
{
	"dnsseed.emzy.de",
};

string uto_little_endian_str(unsigned long long n, int bytes_n = 4, bool is_little_endian = true)
{
	stringstream sstream;
	sstream << hex << n;
	string hex = sstream.str();

	string les;
	if (hex.length() % 2 != 0) hex.insert(0, "0");
	const int n_2add = bytes_n * 2 - hex.length();
	for (int i = 0; i < n_2add; ++i)
		hex.insert(0, "0");

	if (is_little_endian)
	{
		for (int i = hex.length() - 1; i < hex.length(); --i)
		{
			if (i % 2 == 0)
			{
				les += hex[i];
				les += hex[i + 1];
			}
		}
	}

	return les;
}

int main()
{	
	// Example 
	
	tcp::tcp_client client(dns_seeds);
	tcp::converter conv;
	header_chain::POW pow;
	header_chain::dissector dissector;
	repo::buffer buff;

	// Getting block headers in raw format
	string genesis_block = "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04";
	
	//const char* data_to_hash = conv.hex_str_to_little_endian("378rhB5cvJEcbdrAW9byAmVEYYZ12P6agw").c_str();
	//client.setfilter(data_to_hash);

	string headers = client.getheaders(genesis_block);

	string last_header_hash;
	string hex_bits;

	vector<models::header> headers_models = dissector.dissect(headers, last_header_hash, hex_bits);

	if (pow.proof_of_work(headers_models, hex_bits))
	{
		buff.serialize("D:\/headers.dat", headers_models);
	}

	/*
	string bytes = "1010110111110000";
	// Structured block headers models
	string last_header_hash;
	string hex_bits;
	vector<models::header> headers_models = dissector.dissect(headers, last_header_hash, hex_bits);
	
	// POW
	if (pow.proof_of_work(headers_models, hex_bits))
	{
		repo::buffer buff;
		buff.serialize("D:\/" + last_header_hash + ".dat", headers_models);
	}
	

	repo::buffer buff;
	vector<models::header> hdrs = buff.deserialize("D:\/" + last_header_hash + ".dat");
	*/
	
}