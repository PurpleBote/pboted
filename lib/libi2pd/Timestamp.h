/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <thread>
#include <vector>
#include <string>

namespace i2p
{
namespace util
{
	uint64_t GetMillisecondsSinceEpoch ();
	uint64_t GetSecondsSinceEpoch ();
	uint32_t GetMinutesSinceEpoch ();
	uint32_t GetHoursSinceEpoch ();

	void GetCurrentDate (char * date); // returns date as YYYYMMDD string, 9 bytes
	void GetDateString (uint64_t timestamp, char * date); // timestap is seconds since epoch, returns date as YYYYMMDD string, 9 bytes
	void AdjustTimeOffset (int64_t offset); // in seconds from current
}
}

#endif
