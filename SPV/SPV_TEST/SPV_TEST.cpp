#include <iostream>
#include <vector>
#include <string>
#include <boost/asio.hpp>
#include <sstream>

#include "SHA256.h"
#include "spv.h"

using namespace std;
using namespace std::chrono;

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
	header_chain::pow pow;
	header_chain::dissector dissector;

	// Getting block headers in raw format
	string headers = client.getheaders("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

	// Structured block headers models
	vector<models::header> headers_models = dissector.dissect(headers);
	
	// POW
	bool is_correct = pow.proof_of_work(headers_models);
}