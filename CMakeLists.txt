
#project name
PROJECT(Tinyhttpd_for_Windows)
#head file path
INCLUDE_DIRECTORIES(
        include
)
#source directory
AUX_SOURCE_DIRECTORY(. DIR_SRCS)
#set environment variable
SET(TEST_SERVER
        ${DIR_SRCS}
        )
#set extern libraries
SET(LIBRARIES
        .dll
        )
#add executable file
ADD_EXECUTABLE(./bin ${TEST_SERVER})
#add link library
TARGET_LINK_LIBRARIES(./bin ${LIBRARIES})

