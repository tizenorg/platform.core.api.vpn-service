CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(PACKAGE_NAME vpnsvc-daemon)
SET(LIB_NAME ${PACKAGE_NAME})
PROJECT(${LIB_NAME})
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR "\${prefix}/include")
SET(DAEMON_DIR "${CMAKE_SOURCE_DIR}/daemon")
SET(VERSION 0.1)

SET(requires "dlog dbus-1 glib-2.0 gio-2.0 gio-unix-2.0 capi-base-common capi-appfw-package-manager cynara-client cynara-creds-gdbus cynara-session")
SET(pc_requires "capi-base-common")

SET(SRCS
	src/vpnsvc.c
	src/vpndbus.c
	src/vpnerror.c
	src/vpn_service_daemon.c
	src/vpn_service_daemon_main.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
					${CMAKE_SOURCE_DIR}/framework/include
					${CMAKE_SOURCE_DIR}/daemon/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(${PACKAGE_NAME} REQUIRED ${requires})
FOREACH(flag ${${PACKAGE_NAME}_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# Compiler flags
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fPIC -Wall -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -I${DAEMON_DIR}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

ADD_DEFINITIONS("-fPIE")
ADD_DEFINITIONS("-DPREFIX=\"${PREFIX}\"")
ADD_DEFINITIONS("-DFACTORYFS=\"$ENV{FACTORYFS}\"")
ADD_DEFINITIONS("-DDATAFS=\"$ENV{DATADIR}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -Wl,--rpath="${LIBDIR}"")

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT ${DAEMON_DIR}/generated-code.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.
			--generate-c-code generated-code
			--c-generate-object-manager
			--generate-docbook generated-code-docs
			${DAEMON_DIR}/interfaces/org.tizen.vpnsvc.xml
			COMMENT "Generating GDBus .c/.h")

ADD_EXECUTABLE(${PACKAGE_NAME} ${SRCS} ${DAEMON_DIR}/generated-code.c)
TARGET_LINK_LIBRARIES(${PACKAGE_NAME} ${${PACKAGE_NAME}_LDFLAGS} -lrt -ldl -pie)

INSTALL(TARGETS ${PACKAGE_NAME} DESTINATION bin)

