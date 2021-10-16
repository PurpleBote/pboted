FILE(GLOB LIBSAM_SRC *.cpp)
add_library(libsam ${LIBSAM_SRC})
set_target_properties(libsam PROPERTIES PREFIX "")