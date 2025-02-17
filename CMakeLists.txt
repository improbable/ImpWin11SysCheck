cmake_minimum_required(VERSION 3.2)
project(Win11SysCheck CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ../Bin/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ../Bin/)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
	set(LIB_RT_SUFFIX "md")
	set(LIB_RT_OPTION "/MD")

	foreach(flag_var  CMAKE_C_FLAGS  CMAKE_CXX_FLAGS)
		 foreach(config_name  ""  DEBUG  RELEASE  MINSIZEREL  RELWITHDEBINFO)
			set(var_name "${flag_var}")

			if(NOT "${config_name}" STREQUAL "")
				set(var_name "${var_name}_${config_name}")
			endif()
			
			string(REPLACE "/MT" "${LIB_RT_OPTION}" ${var_name} "${${var_name}}")
			set(${var_name} "${${var_name}}" CACHE STRING "" FORCE)
		endforeach()
	endforeach()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MT_BUILD}")
endif()

add_executable (${PROJECT_NAME}
    include/main.h
    src/main.cpp
)


find_package(cpr CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} dxguid PowrProf WinInet Tbs cpr)
