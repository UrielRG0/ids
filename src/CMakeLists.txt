cmake_minimum_required(VERSION 3.11)
project(SistemaIDS)

set(CMAKE_CXX_STANDARD 17)

# Descargar FTXUI para la TUI
include(FetchContent)
FetchContent_Declare(
    ftxui 
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG main
)
FetchContent_MakeAvailable(ftxui)

# Buscar librería de hilos
find_package(Threads REQUIRED)

add_executable(mi_ids main.cpp)

# Ligar hilos, FTXUI y libpcap
target_link_libraries(mi_ids PRIVATE 
    ftxui::screen 
    ftxui::dom 
    ftxui::component 
    pcap 
    Threads::Threads
)
