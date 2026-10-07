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
    if(line MATCHES "[ \t]_?(samsungsds|cryptolab)_" OR
       line MATCHES "[ \t]_?crypto_(kem|sign)_")
        message(FATAL_ERROR "Unprefixed vendored symbol: ${line}")
    endif()
endforeach()
