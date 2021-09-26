// 0 => Success
// -1 => Fail

#include <iostream>
#include <boost/asio.hpp>
#include <boost/dynamic_bitset.hpp>
#include <bitset>
#include "spv.h"
#include <fstream>
#include <sstream>

using namespace boost::asio;

namespace tcp
{
	typedef boost::system::error_code error_code;
	vector<string> tcp_client::dns_seeds;
	vector<string> seeds_ips;


	//Public methods

	tcp_client::tcp_client(vector<string> _dns_seeds)
	{
		dns_seeds = _dns_seeds;
	}

	//Private methods

	void handle_resolve_query(const error_code& erc, ip::tcp::resolver::iterator iter)
	{
		if (erc) return;

		ip::tcp::resolver::iterator end;
		for (; iter != end; ++iter)
		{
			ip::tcp::endpoint endpoint = *iter;
			seeds_ips.push_back(endpoint.address().to_string());
		}
	}

	void tcp_client::get_ips(vector<string>& dns_ips_out)
	{
		io_context ioc;
		ip::tcp::resolver resolver(ioc);

		for (int seed = 0; seed < dns_seeds.size(); ++seed)
		{
			ip::tcp::resolver::query query(dns_seeds[seed], "http");

			resolver.async_resolve(query, handle_resolve_query);
			ioc.run();

			if (!seeds_ips.empty()) break;
		}

		dns_ips_out = seeds_ips;
	}

	void send_getheaders(string ip)
	{
		converter conv;
		message msg;

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		string get_headers = msg.make_message(msg.getheaders_message_payload(1), "getheaders");
		get_headers = conv.hex_str_to_binary(get_headers);
		socket.write_some(buffer(get_headers.data(), get_headers.size()), erc);
	}

	// Public methods
	std::string tcp_client::getheaders(int curr_block_height)
	{
		std::vector<std::string> ips;
		get_ips(ips);

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		for (int i = 0; i < ips.size(); ++i)
		{
			connect(socket, resolver.resolve(ips[i], "8333"), erc);
			boost::asio::socket_base::keep_alive option(true);
			socket.set_option(option);

			if (erc) continue;
			else
			{
				converter conv;
				message msg;
				vector<string> ips;
				get_ips(ips);

				// Version message
				string request = conv.hex_str_to_binary(msg.make_message(msg.version_message_payload(curr_block_height, ips[i], false), "version"));
				if (request.length() == 0) continue;

				socket.send(buffer(request));
				socket.wait(socket.wait_write);

				// Verack message
				string verack_message = conv.hex_str_to_binary(msg.verack_message());
				socket.send(buffer(verack_message));
				socket.wait(socket.wait_write);

				// GetHeaders message
				string get_headers = msg.make_message(msg.getheaders_message_payload(1), "getheaders");
				get_headers = conv.hex_str_to_binary(get_headers);
				if (get_headers.length() == 0) continue;

				Sleep(3000);
				socket.send(buffer(get_headers));
				socket.wait(socket.wait_read);
				Sleep(3000);

				// Response
				stringstream sstream;
				vector<unsigned char> buff(socket.available());

				socket.receive(buffer(buff));
				for (unsigned char ch : buff) sstream << hex << int(ch);
				// pow
				return sstream.str();
				// Call a method which will parse response. Create a header model.
			}
		}
	}
}