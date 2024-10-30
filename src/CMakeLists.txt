if(NOT DEFINED ENV{WIFI_SSID})
    message(FATAL_ERROR "WIFI_SSID Env Var not defined")
endif()

if(NOT DEFINED ENV{WIFI_PASSWORD})
    message(FATAL_ERROR "WIFI_PASSWORD Env Var not defined")
endif()


set(WIFI_SSID $ENV{WIFI_SSID})
set(WIFI_PASSWORD $ENV{WIFI_PASSWORD})

add_executable(${ProjectName}
    #main.cpp
    tcphandler.c
)

target_compile_definitions(${ProjectName} PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    EC2_IP="3.87.249.123"
)

target_include_directories(${ProjectName} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(${ProjectName} 
    pico_stdlib
    #try with poll, then try with threadsafe version (preferred)
    pico_cyw43_arch_lwip_poll
)

pico_enable_stdio_usb(${ProjectName} 1)
pico_add_extra_outputs(${ProjectName})
