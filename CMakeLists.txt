cmake_minimum_required(VERSION 2.6)

PROJECT(umbim C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES cli.c mbim-enum.c mbim-dev.c mbim-msg.c )

SET(LIBS ubox)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3)
ENDIF()

ADD_EXECUTABLE(umbim ${SOURCES})

TARGET_LINK_LIBRARIES(umbim ${LIBS})

INSTALL(TARGETS umbim
	RUNTIME DESTINATION sbin
)
