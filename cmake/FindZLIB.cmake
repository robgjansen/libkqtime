# - Check for the presence of ZLIB
#
# The following variables are set when ZLIB is found:
#  HAVE_ZLIB       = Set to true, if all components of ZLIB
#                          have been found.
#  ZLIB_INCLUDES   = Include path for the header files of ZLIB
#  ZLIB_LIBRARIES  = Link these to use ZLIB

## -----------------------------------------------------------------------------
## Check for the header files

find_path (ZLIB_INCLUDES zlib.h
  PATHS /usr/local/include /usr/include /sw/include PATH_SUFFIXES zlib zlib/include
  )

## -----------------------------------------------------------------------------
## Check for the library

find_library (ZLIB_LIBRARIES z
  PATHS /usr/local/lib64 /usr/lib64 /lib64 /usr/lib/x86_64-linux-gnu/ /usr/local/lib /usr/lib  /lib /sw/lib /usr/lib/i386-linux-gnu
  )

## -----------------------------------------------------------------------------
## Actions taken when all components have been found

if (ZLIB_INCLUDES AND ZLIB_LIBRARIES)
  set (HAVE_ZLIB TRUE)
else (ZLIB_INCLUDES AND ZLIB_LIBRARIES)
  if (NOT ZLIB_FIND_QUIETLY)
    if (NOT ZLIB_INCLUDES)
      message (STATUS "Unable to find ZLIB header files!")
    endif (NOT ZLIB_INCLUDES)
    if (NOT ZLIB_LIBRARIES)
      message (STATUS "Unable to find ZLIB library files!")
    endif (NOT ZLIB_LIBRARIES)
  endif (NOT ZLIB_FIND_QUIETLY)
endif (ZLIB_INCLUDES AND ZLIB_LIBRARIES)

if (HAVE_ZLIB)
  if (NOT ZLIB_FIND_QUIETLY)
    message (STATUS "Found components for ZLIB")
    message (STATUS "ZLIB_INCLUDES = ${ZLIB_INCLUDES}")
    message (STATUS "ZLIB_LIBRARIES     = ${ZLIB_LIBRARIES}")
  endif (NOT ZLIB_FIND_QUIETLY)
else (HAVE_ZLIB)
  if (ZLIB_FIND_REQUIRED)
    message (FATAL_ERROR "Could not find ZLIB!")
  endif (ZLIB_FIND_REQUIRED)
endif (HAVE_ZLIB)

mark_as_advanced (
  HAVE_ZLIB
  ZLIB_LIBRARIES
  ZLIB_INCLUDES
  )
