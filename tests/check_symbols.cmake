if(NOT DEFINED NM_EXECUTABLE OR NOT DEFINED LIBRARY_FILE)
    message(FATAL_ERROR "NM_EXECUTABLE and LIBRARY_FILE are required")
endif()

execute_process(
    COMMAND "${NM_EXECUTABLE}" -g "${LIBRARY_FILE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE symbols
    ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "nm failed: ${error}")
endif()

string(REPLACE "\n" ";" lines "${symbols}")
foreach(line IN LISTS lines)
    if(NOT line MATCHES "[ \t][TDBRSCG] ([^ \t]+)$")
        continue()
    endif()

    set(symbol "${CMAKE_MATCH_1}")
    if(symbol MATCHES "^_?kpqc_" OR
       symbol MATCHES "^_+Z" OR
       symbol MATCHES "^_+clang_call_terminate$")
        continue()
    endif()

    message(FATAL_ERROR "Unexpected global definition: ${symbol}")
endforeach()
