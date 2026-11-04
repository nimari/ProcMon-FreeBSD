# SPDX-License-Identifier: MIT
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef suffix)
set(directory "${TEST_PARENT}/storage-test-${suffix}")
file(MAKE_DIRECTORY "${directory}")
execute_process(COMMAND "${TEST_EXECUTABLE}" "${directory}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Storage test failed; evidence retained at ${directory}")
endif()
file(REMOVE_RECURSE "${directory}")
