cmake_minimum_required(VERSION 3.20.3)

project(DVS 
    VERSION 101
    DESCRIPTION "Decentralized Voting System"
    LANGUAGES CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wshadow -Weffc++ -pthread -O2")

file(GLOB HEADERS include/*.hpp)
file(GLOB SOURCE_FILES src/*.cpp)
foreach(SOURCE_FILE ${SOURCE_FILES})
	get_filename_component(TARGET_NAME ${SOURCE_FILE} NAME_WE)
	add_executable(${TARGET_NAME} ${SOURCE_FILE})
	if(PRECOMPILE)
		target_precompile_headers(${TARGET_NAME} PUBLIC ${HEADERS})
	endif()

	set(OPENSSL_USE_STATIC_LIBS TRUE)
	find_package(OpenSSL REQUIRED)
	if(NOT OPENSSL_FOUND)
		message(FATAL_ERROR "Fatal error : OpenSSL required.")
	else()
		include_directories(${OPENSSL_INCLUDE_DIRS})
		target_link_libraries(${TARGET_NAME} ${OPENSSL_LIBRARIES})
	endif(NOT OPENSSL_FOUND)

	set(Boost_USE_STATIC_LIBS       OFF) 
	set(Boost_USE_MULTITHREADED     ON)
	set(Boost_USE_STATIC_RUNTIME    OFF)
	find_package(Boost 1.76.0 REQUIRED)
	if(NOT Boost_FOUND)
		message(FATAL_ERROR "Fatal error: Boost (version >= 1.76.0) required.")
	else()
		include_directories(${Boost_INCLUDE_DIRS})
		target_link_libraries(${TARGET_NAME} ${Boost_LIBRARIES})
	endif(NOT Boost_FOUND)

	include(FetchContent)
	FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/whoshuu/cpr.git GIT_TAG f4622efcb59d84071ae11404ae61bd821c1c344b)
	FetchContent_MakeAvailable(cpr)
	target_link_libraries(${TARGET_NAME} cpr::cpr)

endforeach(SOURCE_FILE ${SOURCE_FILES})
