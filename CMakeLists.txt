cmake_minimum_required(VERSION 3.10)
project(ics_radar_toolkit CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MODBUS REQUIRED libmodbus)

add_executable(track_sim simulator/track_sim.cpp)
target_include_directories(track_sim PRIVATE ${MODBUS_INCLUDE_DIRS})
target_link_libraries(track_sim ${MODBUS_LIBRARIES})
target_compile_options(track_sim PRIVATE ${MODBUS_CFLAGS_OTHER} -Wall -Wextra)

add_executable(modbus_toolkit toolkit/modbus_toolkit.cpp)
target_include_directories(modbus_toolkit PRIVATE ${MODBUS_INCLUDE_DIRS})
target_link_libraries(modbus_toolkit ${MODBUS_LIBRARIES})
target_compile_options(modbus_toolkit PRIVATE ${MODBUS_CFLAGS_OTHER} -Wall -Wextra)

add_executable(modbus_gateway gateway/modbus_gateway.cpp)
target_compile_options(modbus_gateway PRIVATE -Wall -Wextra)
