# - Check for the presence of PCAP
#
# The following variables are set when PCAP is found:
#  HAVE_PCAP       = Set to true, if all components of PCAP
#                          have been found.
#  PCAP_INCLUDES   = Include path for the header files of PCAP
#  PCAP_LIBRARIES  = Link these to use PCAP

## -----------------------------------------------------------------------------
## Check for the header files

find_path (PCAP_INCLUDES pcap.h
  PATHS /usr/local/include /usr/include /sw/include PATH_SUFFIXES pcap pcap/include
  )

## -----------------------------------------------------------------------------
## Check for the library

find_library (PCAP_LIBRARIES pcap
  PATHS /usr/local/lib64 /usr/lib64 /lib64 /usr/lib/x86_64-linux-gnu/ /usr/local/lib /usr/lib  /lib /sw/lib /usr/lib/i386-linux-gnu
  )

## -----------------------------------------------------------------------------
## Actions taken when all components have been found

if (PCAP_INCLUDES AND PCAP_LIBRARIES)
  set (HAVE_PCAP TRUE)
else (PCAP_INCLUDES AND PCAP_LIBRARIES)
  if (NOT PCAP_FIND_QUIETLY)
    if (NOT PCAP_INCLUDES)
      message (STATUS "Unable to find PCAP header files!")
    endif (NOT PCAP_INCLUDES)
    if (NOT PCAP_LIBRARIES)
      message (STATUS "Unable to find PCAP library files!")
    endif (NOT PCAP_LIBRARIES)
  endif (NOT PCAP_FIND_QUIETLY)
endif (PCAP_INCLUDES AND PCAP_LIBRARIES)

if (HAVE_PCAP)
  if (NOT PCAP_FIND_QUIETLY)
    message (STATUS "Found components for PCAP")
    message (STATUS "PCAP_INCLUDES = ${PCAP_INCLUDES}")
    message (STATUS "PCAP_LIBRARIES     = ${PCAP_LIBRARIES}")
  endif (NOT PCAP_FIND_QUIETLY)
else (HAVE_PCAP)
  if (PCAP_FIND_REQUIRED)
    message (FATAL_ERROR "Could not find PCAP!")
  endif (PCAP_FIND_REQUIRED)
endif (HAVE_PCAP)

mark_as_advanced (
  HAVE_PCAP
  PCAP_LIBRARIES
  PCAP_INCLUDES
  )
