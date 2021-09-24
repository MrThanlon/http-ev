cmake_minimum_required(VERSION 3.14)
project(http-ev-example C)

set(CMAKE_C_STANDARD 99)
include_directories(/usr/local/include)
link_directories(/usr/local/lib)
include(FetchContent)
FetchContent_Declare(llhttp URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v6.0.5.tar.gz")
FetchContent_MakeAvailable(llhttp)

# add_compile_options(-Ofast)

add_executable(http-ev-example src/main.c src/http.c src/http.h)
target_link_libraries(http-ev-example ev llhttp)
