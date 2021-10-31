#include <iostream>
#include <vector>
#include <string>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include "SHA256.h"
#include <stdio.h>
#include "spv.h"

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

int main()
{
	tcp::tcp_client client(dns_seeds);
	header_chain::POW pow;
	header_chain::dissector dissector;

	// Getting block headers in raw format
	string headers = client.getheaders("00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04");

	// Structured block headers models
	string last_header_hash;
	vector<models::header> headers_models = dissector.dissect(headers, last_header_hash);

	// POW
	if (pow.proof_of_work(headers_models))
	{
		
	}
}