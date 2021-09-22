#pragma once

#include <iostream>

namespace tcp
{
	class header
	{
		public:
			int32_t version;
			char block[32];
			char merkle_root[32];
			uint32_t timestamp;
			uint32_t bits;
			uint32_t nonce;
	};
}