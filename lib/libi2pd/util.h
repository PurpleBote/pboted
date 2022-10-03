/*
* Copyright (c) 2013-2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>

namespace i2p
{
namespace util
{

	template<class T>
	class MemoryPool
	{
		static_assert(sizeof(T) >= sizeof(void*), "size cannot be less that general pointer size");

		public:

			MemoryPool (): m_Head (nullptr) {}
			~MemoryPool ()
			{
				CleanUp ();
			}

			void CleanUp ()
			{
				CleanUp (m_Head);
				m_Head = nullptr;
			}

			template<typename... TArgs>
			T * Acquire (TArgs&&... args)
			{
				if (!m_Head) return new T(std::forward<TArgs>(args)...);
				else
				{
					auto tmp = m_Head;
					m_Head = static_cast<T*>(*(void * *)m_Head); // next
					return new (tmp)T(std::forward<TArgs>(args)...);
				}
			}

			void Release (T * t)
			{
				if (!t) return;
				t->~T ();
				*(void * *)t = m_Head; // next
				m_Head = t;
			}

			template<typename... TArgs>
			std::unique_ptr<T, std::function<void(T*)> > AcquireUnique (TArgs&&... args)
			{
				return std::unique_ptr<T, std::function<void(T*)> >(Acquire (std::forward<TArgs>(args)...),
					std::bind (&MemoryPool<T>::Release, this, std::placeholders::_1));
			}

			template<typename... TArgs>
			std::shared_ptr<T> AcquireShared (TArgs&&... args)
			{
				return std::shared_ptr<T>(Acquire (std::forward<TArgs>(args)...),
					std::bind (&MemoryPool<T>::Release, this, std::placeholders::_1));
			}

		protected:

			void CleanUp (T * head)
			{
				while (head)
				{
					auto tmp = head;
					head = static_cast<T*>(*(void * *)head); // next
					::operator delete ((void *)tmp);
				}
			}

		protected:

			T * m_Head;
	};

	template<class T>
	class MemoryPoolMt: public MemoryPool<T>
	{
		public:

			MemoryPoolMt () {}
			template<typename... TArgs>
			T * AcquireMt (TArgs&&... args)
			{
				if (!this->m_Head) return new T(std::forward<TArgs>(args)...);
				std::lock_guard<std::mutex> l(m_Mutex);
				return this->Acquire (std::forward<TArgs>(args)...);
			}

			void ReleaseMt (T * t)
			{
				std::lock_guard<std::mutex> l(m_Mutex);
				this->Release (t);
			}

			template<template<typename, typename...>class C, typename... R>
			void ReleaseMt(const C<T *, R...>& c)
			{
				std::lock_guard<std::mutex> l(m_Mutex);
				for (auto& it: c)
					this->Release (it);
			}

			template<typename... TArgs>
			std::shared_ptr<T> AcquireSharedMt (TArgs&&... args)
			{
				return std::shared_ptr<T>(AcquireMt (std::forward<TArgs>(args)...),
					std::bind<void (MemoryPoolMt<T>::*)(T *)> (&MemoryPoolMt<T>::ReleaseMt, this, std::placeholders::_1));
			}

			void CleanUpMt ()
			{
				T * head;
				{
					std::lock_guard<std::mutex> l(m_Mutex);
					head = this->m_Head;
					this->m_Head = nullptr;
				}
				if (head) this->CleanUp (head);
			}

		private:

			std::mutex m_Mutex;
	};

	void SetThreadName (const char *name);

	template<typename T>
	class SaveStateHelper
	{
		public:

			SaveStateHelper (T& orig): m_Original (orig), m_Copy (orig) {};
			~SaveStateHelper () { m_Original = m_Copy; };

		private:

			T& m_Original;
			T m_Copy;
	};
}
}

#endif
