add_executable(tcp_responder tcp/responder.c)
target_link_libraries(tcp_responder PRIVATE edhoc-c::edhoc-c)

add_executable(tcp_initiator tcp/initiator.c)
target_link_libraries(tcp_initiator PRIVATE edhoc-c::edhoc-c)

add_executable(coap_responder coap/responder.c coap/nanocoap.c)
target_link_libraries(coap_responder PRIVATE edhoc-c::edhoc-c)
