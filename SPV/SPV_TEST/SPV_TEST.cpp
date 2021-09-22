#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <sstream>
#include <chrono>
#include <spv.h>
#include <boost/dynamic_bitset.hpp>
#include <bitset>
#include <boost/asio.hpp>
#include <sstream>
#include "SHA256.h"

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
	"seed.bitcoin.sipa.be",
};

int main()
{
	tcp::tcp_client client(dns_seed);
	client.getheaders(1);
}