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

	// Public methods

	int tcp_client::send_verack_message(string ip)
	{
		converter conv;
		message msg;

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		string request = conv.hex_str_to_binary(msg.verack_message());

		connect(socket, resolver.resolve(ip, "8333"), erc);
		if (!erc)
		{
			socket.write_some(buffer(request.data(), request.size()), erc);
			socket.wait(socket.wait_read);

			vector<unsigned char> reply;
			if (!erc) socket.read_some(buffer(reply.data(), reply.size()), erc);

			for (unsigned char uch : reply) cout << uch;
		}

		return 0;
	}

	int tcp_client::getheaders(int curr_block_height)
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

			if (erc) continue;
			else
			{
				//Cooking request
				converter conv;

				// Feeding version_message by bytes;
				vector<string> ips;
				get_ips(ips);
				message msg;
				string request = conv.hex_str_to_binary(msg.make_message(msg.version_message_payload(curr_block_height, ips[i], false), "version"));
				if (request.length() == 0) continue;

				if (request.size() > 1)
				{
					socket.write_some(buffer(request.data(), request.size()));
					socket.wait(socket.wait_read);

					if (erc) continue;
					int verack = send_verack_message(ips[i]);
					
					if (verack == 0)
					{
						request = conv.hex_str_to_binary(msg.make_message(msg.getheaders_message_payload(1), "getheaders"));

						socket.write_some(buffer(request.data(), request.size()), erc);
						socket.wait(socket.wait_read);

						if (erc) throw exception("Проблема при отправке getheaders message");

						vector<unsigned char> headerv;
						socket.read_some(buffer(headerv.data(), headerv.size()));

						// Call a method which will parse response. Create a header model.
					}
				}

			}
		}

		return 0;
	}

	int tcp_client::send_ping_message()
	{
		std::vector<std::string> ips;
		converter conv;
		message msg;
		get_ips(ips);

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		for (int i = 0; i < ips.size(); ++i)
		{
			std::cout << "Trying establish connection with " << ips[i] << std::endl;
			connect(socket, resolver.resolve(ips[i], "8333"), erc);
			std::cout << "Connection status: " << erc.message() << std::endl;
			std::cout << "----------------------------------------------------" << std::endl;
			std::cout << std::endl;
			if (erc) continue;
			else
			{
				vector<string> ips;
				get_ips(ips);
				string request = conv.hex_str_to_binary(msg.make_message(msg.ping_message_payload(), "ping"));
				cout << "String sending bytes: " << request << endl;
				if (request.length() == 0) continue;

				cout << "\nBytes to send: " << request.size() << "bytes" << endl;
				if (request.size() > 1)
				{
					socket.write_some(buffer(request.data(), request.size()));
					if (erc) continue;
					else
					{
						auto bytes_available = socket.available();
						cout << "Avalible bytes to read: " << bytes_available << endl;
						vector<char> response(bytes_available);
						socket.read_some(buffer(response.data(), response.size()), erc);
						for (char ch : response)
							std::cout << ch << " ";
					}
				}
				std::cout << "----------------------------------------------------" << std::endl;
				std::cout << std::endl;
			}
		}

		return 0;
	}
}