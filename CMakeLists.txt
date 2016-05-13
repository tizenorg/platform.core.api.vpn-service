CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("capi-vpn-service-pkg")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compiler flags ##################################

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX ${PREFIX}/bin)
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR ${PREFIX}/include)

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set compiler warning flags

# ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings

ADD_SUBDIRECTORY(framework)
ADD_SUBDIRECTORY(daemon)
ADD_SUBDIRECTORY(test)

