add_executable(responder responder.c)
target_link_libraries(responder PRIVATE edhoc-c::edhoc-c)

add_executable(initiator initiator.c)
target_link_libraries(initiator PRIVATE edhoc-c::edhoc-c)
