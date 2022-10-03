/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <time.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <chrono>
#include <future>

#include "I2PEndian.h"
#include "Log.h"
#include "Timestamp.h"
#include "util.h"

#ifdef _WIN32
	#ifndef _WIN64
		#define _USE_32BIT_TIME_T
	#endif
#endif

namespace i2p
{
namespace util
{
	static uint64_t GetLocalMillisecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static uint64_t GetLocalSecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static uint32_t GetLocalMinutesSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::minutes>(
			std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static uint32_t GetLocalHoursSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::hours>(
			std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static int64_t g_TimeOffset = 0; // in seconds

	uint64_t GetMillisecondsSinceEpoch ()
	{
		return GetLocalMillisecondsSinceEpoch () + g_TimeOffset*1000;
	}

	uint64_t GetSecondsSinceEpoch ()
	{
		return GetLocalSecondsSinceEpoch () + g_TimeOffset;
	}

	uint32_t GetMinutesSinceEpoch ()
	{
		return GetLocalMinutesSinceEpoch () + g_TimeOffset/60;
	}

	uint32_t GetHoursSinceEpoch ()
	{
		return GetLocalHoursSinceEpoch () + g_TimeOffset/3600;
	}

	void GetCurrentDate (char * date)
	{
		GetDateString (GetSecondsSinceEpoch (), date);
	}

	void GetDateString (uint64_t timestamp, char * date)
	{
		using clock = std::chrono::system_clock;
		auto t = clock::to_time_t (clock::time_point (std::chrono::seconds(timestamp)));
		struct tm tm;
#ifdef _WIN32
		gmtime_s(&tm, &t);
		sprintf_s(date, 9, "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#else
		gmtime_r(&t, &tm);
		sprintf(date, "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#endif
	}

	void AdjustTimeOffset (int64_t offset)
	{
		g_TimeOffset += offset;
	}
}
}
