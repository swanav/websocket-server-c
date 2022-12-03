cmake_minimum_required(VERSION 3.14)

project(
    WebSocketServer
    LANGUAGES C CXX
    DESCRIPTION "A simple Websocket Server on BSD Sockets API with supports for callback methods for event processing"
)

set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)
    
set(TARGET "linux" CACHE STRING "Build Target for ${PROJECT_NAME} applications")
set(ENABLE_COMPONENT_TEST OFF CACHE BOOL "Should build tests for component libraries")
# Detect ESP-IDF Build using idf.py cmake wrapper
if(${ESP_PLATFORM})
	set(TARGET "esp32")
endif()


# Set flags for Target
message(STATUS "Building ${PROJECT_NAME} for ${TARGET}")
if("${TARGET}" STREQUAL "esp32")
    add_definitions(-DBUILD_TARGET_ESP32)
elseif("${TARGET}" STREQUAL "linux")
    add_definitions(-DBUILD_TARGET_LINUX)
	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
			set(Python_FIND_STRATEGY LOCATION)
			find_package(Python COMPONENTS Interpreter)
			if(Python_Interpreter_FOUND)
				set(PYTHON_EXECUTABLE ${Python_EXECUTABLE})
			endif()
			include( cmake/CodeCoverage.cmake )
			SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 --coverage -fprofile-arcs -ftest-coverage")
			SET(GCC_COVERAGE_LINK_FLAGS    "-lgcov")
			SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
			SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
			SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

			SETUP_TARGET_FOR_COVERAGE_COBERTURA( GenerateCoverage ctest Coverage )
		endif()
	endif()
elseif("${TARGET}" STREQUAL "windows")
    add_definitions(-DBUILD_TARGET_WINDOWS)
endif()

if(NOT "${TARGET}" STREQUAL "esp32")
	if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
		include(CTest)
	# ========================================================= 
		# Download and unpack googletest at configure time
		configure_file(GTestCMakeLists.txt.in googletest-download/CMakeLists.txt)
		execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
		RESULT_VARIABLE result
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
		message(FATAL_ERROR "CMake step for googletest failed: ${result}")
		endif()
		execute_process(COMMAND ${CMAKE_COMMAND} --build .
		RESULT_VARIABLE result
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
		message(FATAL_ERROR "Build step for googletest failed: ${result}")
		endif()

		# Prevent overriding the parent project's compiler/linker
		# settings on Windows
		set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

		# Add googletest directly to our build. This defines
		# the gtest and gtest_main targets.
		add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
						${CMAKE_CURRENT_BINARY_DIR}/googletest-build
						EXCLUDE_FROM_ALL)

		# The gtest/gtest_main targets carry header search path
		# dependencies automatically when using CMake 2.8.11 or
		# later. Otherwise we have to add them here ourselves.
		if (CMAKE_VERSION VERSION_LESS 2.8.11)
		include_directories("${gtest_SOURCE_DIR}/include")
		endif()
	# ========================================================= 
    endif()
endif()


# Include Libraries and Sources

add_subdirectory(libs/LinkedList)
add_subdirectory(libs/llhttp)
add_subdirectory(src)

if(NOT "${TARGET}" STREQUAL "esp32")

if(NOT ENABLE_COMPONENT_TEST)
	set(ENABLE_PROGRAMS OFF CACHE BOOL "Enable building Programs")
	set(ENABLE_TESTING OFF CACHE BOOL "Enable building Tests")

	# Disable building programs and tests in mbedtls
	set(PROJECT_ENABLE_PROGRAMS ENABLE_PROGRAMS)
	set(PROJECT_ENABLE_TESTING ENABLE_TESTING)
endif()
	add_subdirectory(libs/mbedtls)
if(NOT ENABLE_COMPONENT_TEST)
	set(ENABLE_PROGRAMS PROJECT_ENABLE_PROGRAMS)
	set(ENABLE_TESTING PROJECT_ENABLE_TESTING)
endif()

	add_subdirectory(examples)

endif()

