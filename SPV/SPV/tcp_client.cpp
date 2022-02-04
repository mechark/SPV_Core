#include <iostream>
#include <boost/asio.hpp>
#include "spv.h"
#include <fstream>
#include <iomanip>
#include <sstream>


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
		ip::tcp::socket sock(ioc);

		for (size_t seed = 0; seed < dns_seeds.size(); ++seed)
		{
			ip::tcp::resolver::query query(dns_seeds[seed], "http");

			resolver.async_resolve(query, handle_resolve_query);
			ioc.run();

			if (!seeds_ips.empty()) break;
		}

		if (seeds_ips.size() != 0) dns_ips_out = seeds_ips;
		else
		{
			cout << "error in tcp_client::get_ips method. Seed ips vector is empty";
			terminate();
		}
			
	}

	int tcp_client::grab_payload_length(string message_header, int& headers_starts_at)
	{
		// This numbers (26 and 20) take from bitcoin protocol byte order.
		string headers_command = "d9686561646572730000000000";
		unsigned int start_headers_index = message_header.find(headers_command) + headers_command.length();
		headers_starts_at = start_headers_index + 18;
		string payload_length_hex = message_header.substr(start_headers_index, 8);

		converter conv;
		start_headers_index = conv.hex_str_toi(payload_length_hex, true);

		return start_headers_index;
	}

	

	// Public methods
	void tcp_client::setfilter(const char* data_to_hash)
	{
		std::vector<std::string> ips;
		get_ips(ips);

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		for (size_t i = 0; i < ips.size(); ++i)
		{
			connect(socket, resolver.resolve(ips[i], "8333"), erc);

			if (erc) continue;
			else
			{
				converter conv;
				message msg;
				vector<string> ips;
				get_ips(ips);

				// Version message
				std::string request = conv.hex_str_to_binary(msg.make_message(msg.version_message_payload(ips[i], false), "version"));
				if (request.length() == 0) continue;

				socket.send(buffer(request));
				socket.wait(socket.wait_write);

				// Verack message
				string verack_message = conv.hex_str_to_binary(msg.verack_message());
				socket.send(buffer(verack_message));
				socket.wait(socket.wait_read);

				// Filterload message
				string filterload_payload = msg.filterload_message_payload(data_to_hash, 1);
				string filterload_message = msg.make_message(filterload_payload, "filterload");
				socket.send(buffer(conv.hex_str_to_binary(filterload_message)));
				socket.wait(socket.wait_read);
			}
		}
	}

	std::string tcp_client::getheaders(string start_block_header)
	{
		std::vector<std::string> ips;
		get_ips(ips);

		io_context ioc;
		ip::tcp::resolver resolver(ioc);
		ip::tcp::socket socket(ioc);
		error_code erc;

		for (size_t i = 0; i < ips.size(); ++i)
		{
			connect(socket, resolver.resolve(ips[i], "8333"), erc);

			if (erc) continue;
			else
			{
				converter conv;
				message msg;
				vector<string> ips;
				get_ips(ips);

				// Version message
				std::string request = conv.hex_str_to_binary(msg.make_message(msg.version_message_payload(ips[i], false), "version"));
				if (request.length() == 0) continue;

				socket.send(buffer(request));
				socket.wait(socket.wait_write);

				// Verack message
				string verack_message = conv.hex_str_to_binary(msg.verack_message());
				socket.send(buffer(verack_message));
				socket.wait(socket.wait_read);

				// GetHeaders message forming
				std::string block_hash = start_block_header;
				std::string get_headers = msg.make_message(msg.getheaders_message_payload(block_hash), "getheaders");
				get_headers = conv.hex_str_to_binary(get_headers);
				if (get_headers.length() == 0) continue;

				// Sending
				socket.send(buffer(get_headers));
				socket.wait(socket.wait_read);
				Sleep(400);

				// Response
				stringstream sstream;
				vector<char> buff(1024 * 200);

				socket.read_some(buffer(buff.data(), buff.size()));

				sstream << hex << std::setfill('0');
				for (unsigned char ch : buff) sstream << std::setw(2) << static_cast<unsigned>(ch);
				string response = sstream.str();

				// Selecting headers bytes from response
				int ifrom = 0;
				int message_payload_length = grab_payload_length(response, ifrom);
				message_payload_length = (message_payload_length - 1) * 2;
				string headers = response.substr(ifrom, message_payload_length);

				return headers;
			}
		}
	}
}