CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("capi-vpn-service-pkg")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compiler flags ##################################

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX ${PREFIX}/bin)
SET(LIBDIR ${PREFIX}/lib)
SET(INCLUDEDIR ${PREFIX}/include)

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set compiler warning flags

#ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")
ADD_DEFINITIONS("-DSMACK_ENABLED")

IF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
    ADD_DEFINITIONS("-DTIZEN_DEBUG_ENABLE")
    ADD_DEFINITIONS("-DBUILD_TYPE_DEBUG")
ENDIF (CMAKE_BUILD_TYPE MATCHES "DEBUG")

ADD_SUBDIRECTORY(framework)
ADD_SUBDIRECTORY(daemon)
ADD_SUBDIRECTORY(test)

