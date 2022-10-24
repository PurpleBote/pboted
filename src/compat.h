/**
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifndef BOTE_SRC_COMPATH_H
#define BOTE_SRC_COMPATH_H

/* make_unique for C++11 */
#if __cplusplus == 201103L
#ifndef COMPAT_STD_MAKE_UNIQUE
#define COMPAT_STD_MAKE_UNIQUE
namespace std
{

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

} /* namespace std */
#endif /* COMPAT_STD_MAKE_UNIQUE */
#endif /* __cplusplus == 201103L */

/* filesystem for C++11 and C++17 */
#if defined(__has_include)
# if __cplusplus >= 201703L && __has_include(<filesystem>)
    #pragma message ( "Used C++17 <filesystem>" )
    #include <filesystem>
    namespace nsfs = std::filesystem;
# elif __cplusplus >= 201103L && __has_include(<boost/filesystem.hpp>)
    #pragma message ( "Used <boost/filesystem.hpp>" )
    #include <boost/filesystem.hpp>
    namespace nsfs = boost::filesystem;
# else
#    error Missing the <filesystem> header!
# endif
#else
#  error Missing the "__has_include" module!
#endif

#endif /* BOTE_SRC_COMPATH_H*/
