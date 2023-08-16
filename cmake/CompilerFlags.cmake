# CompilerFlags.cmake - Set recommended compiler flags.
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

include(CMakePrintHelpers)

option(ENABLE_WARNING_FLAGS "Enable compiler warnings" OFF)
option(ENABLE_PIE_FLAG      "Enable position independent executables" ON)
option(ENABLE_SANITIZE_CFI  "Enable -sanitize=cfi" ON)
option(ENABLE_SPECTRE_FLAGS "Enable Spectre mitigations" ON)

#-----------------------------------------------------------------------
# Get list of security flags.
#
# Each macro implements a section of the C & C++ Compiler Flag Standards
# in the Intel Secure Coding Standards.
#-----------------------------------------------------------------------
function(_get_security_flags_list config cflags)

  # Compiler Warnings and Error Detection
  macro(setCompilerWarnings config cflags)
    if(${config} STREQUAL "Debug")
      list(APPEND ${cflags}
        -Wall
        -Wextra
      )
    else()
      list(APPEND ${cflags}
        -Wall
        -Wextra
        -Werror
      )
    endif()
  endmacro()

  # Control Flow Integrity
  macro(setFlowIntegrity config cflags)
    if(ENABLE_SANITIZE_CFI)
      list(APPEND ${cflags} -fsanitize=cfi)
    endif()

    if(NOT ${config} STREQUAL "Debug")
      list(APPEND ${cflags}
        -flto                 # link-time optimization
        -fvisibility=hidden   # all ELF symbols are hidden by default
      )
    endif()
  endmacro()

  # Format String Defense
  macro(setFormatDefense config cflags)
    if(${config} STREQUAL "Debug")
      list(APPEND ${cflags}
        -Wformat
        -Wformat-security
      )
    else()
      list(APPEND ${cflags}
        -Wformat
        -Wformat-security
        -Werror=format-security
      )
    endif()
  endmacro()

  # Inexecutable Stack
  macro(setStackDefense config cflags)
    if(NOT ${config} STREQUAL "Debug")
      list(APPEND ${cflags}
        # passed to linker
        # -z noexecstack
        -Wl,-z,noexecstack
      )
    endif()
  endmacro()

  # Position Independent Execution
  macro(setPIE config cflags)
    list(APPEND ${cflags}
      # passed to compiler
      -fPIE
      # passed to linker
      -pie
    )
  endmacro()

  # Preprocessor Macros
  macro(setFortfy config cflags)
    list(APPEND ${cflags}
      -D_FORTIFY_FLAGS=2
    )
  endmacro()

  # Read-only Relocation
  macro(setRelocation config cflags)
    if(NOT ${config} STREQUAL "Release")
      list(APPEND ${cflags}
        # passed to linker
        -Wl,-z,relro
      )
    endif()
  endmacro()

  # Bounds Check Bypass (Spectre Variant 1)
  macro(setBoundsCheck config cflags)
    list(APPEND ${cflags}
      -mconditional-branch=keep
      -mconditional-branch=pattern-report
      -mconditonal-branch=pattern-fix
    )
  endmacro()

  # Branch Target Injection (Spectre Variant 2)
  macro(setTargetInjection config cflags)
    list(APPEND ${cflags}
      -mretpoline
    )
  endmacro()

  set(_cflags)
  set(_mode ${config})

  if(ENABLE_WARNING_FLAGS)
    setCompilerWarnings(config _cflags)
  endif()

  setFlowIntegrity(config _cflags)
  setFormatDefense(config _cflags)
  setStackDefense(config _cflags)
  if(ENABLE_PIE_FLAG)
    setPIE(config _cflags)
  endif()
  setRelocation(config _cflags)

  if(ENABLE_SPECTRE_FLAGS)
    setBoundsCheck(config _cflags)
    setTargetInjection(config _cflags)
  endif()

  set(${cflags} ${_cflags} PARENT_SCOPE)

endfunction(_get_security_flags_list)

#-----------------------------------------------------------------------
# Get extra compiler and linker flags.
#-----------------------------------------------------------------------
function(_get_extra_compiler_flags CFLAGS LDFLAGS)

  # Compiler flags
  string(JOIN " " cflags
      -pipe
      -feliminate-unused-debug-types
  )

  # Linker Flags
  string(JOIN " " ldflags
      -Wl,-O1
      -Wl,--hash-style=gnu
      -Wl,--as-needed
      -Wl,-z,now
  )

  set(${CFLAGS} ${cflags} PARENT_SCOPE)
  set(${LDFLAGS} ${ldflags} PARENT_SCOPE)

endfunction(_get_extra_compiler_flags)

#-----------------------------------------------------------------------
# Define SECURITY_FLAGS_<CONFIG> variables.
#-----------------------------------------------------------------------
function(define_security_flags_variables)
  foreach(config Debug Release)
    _get_security_flags_list(${config} flagsList)

    # SECURITY_FLAGS_<CONFIG>_LIST
    string(TOUPPER ${config} CONFIG)
    set(SECURITY_FLAGS_${CONFIG}_LIST "${flagsList}" CACHE STRING
        "List of security flags for ${CONFIG} builds")

    # SECURITY_FLAGS_<CONFIG>
    list(JOIN flagsList " " flags)
    set(SECURITY_FLAGS_${CONFIG} "${flags}" CACHE STRING
        "Security flags for ${CONFIG} builds")
  endforeach()
endfunction(define_security_flags_variables)

set(_COMPILER_FLAGS_CONFIGS DEBUG MINSIZEREL RELEASE RELWITHDEBINFO)
set(_COMPILER_FLAGS_RELEASE_CONFIGS MINSIZEREL RELEASE RELWITHDEBINFO)

#-----------------------------------------------------------------------
# Define compiler and linker INIT variables.
#-----------------------------------------------------------------------
function(define_compiler_init_variables)
  # These are the built-in defaults.
  set(default_flags_DEBUG "-g")
  set(default_flags_MINSIZEREL "-Os -DNDEBUG")
  set(default_flags_RELEASE "-O3 -DNDEBUG")
  set(default_flags_RELWITHDEBINFO "-O2 -g -DNDEBUG")

  _get_extra_compiler_flags(CFLAGS LDFLAGS)

  foreach(LANG C CXX)
    # CMAKE_<LANG>_FLAGS_DEBUG_INIT
    # Uses the DEBUG security flags.
    set(VAR "CMAKE_${LANG}_FLAGS_DEBUG_INIT")
    string(JOIN " " VALUE
        "${default_flags_DEBUG}"
        "${CFLAGS}"
        "${SECURITY_FLAGS_DEBUG}")
    set(${VAR} "${VALUE}" CACHE STRING "")
    mark_as_advanced(${VAR})

    # CMAKE_<LANG>_FLAGS_<CONFIG>_INIT
    # These configs all use the RELEASE security flags.
    foreach(CONFIG ${_COMPILER_FLAGS_RELEASE_CONFIGS})
      set(VAR CMAKE_${LANG}_FLAGS_${CONFIG}_INIT)
      string(JOIN " " VALUE
          "${default_flags_${CONFIG}}"
          "${CFLAGS}"
          "${SECURITY_FLAGS_RELEASE}")
      set(${VAR} "${VALUE}" CACHE STRING "")
      mark_as_advanced(${VAR})
    endforeach()
  endforeach()

  # CMAKE_<TYPE>_LINKER_FLAGS_<CONFIG>_INIT
  foreach(CONFIG ${_COMPILER_FLAGS_CONFIGS})
    foreach(TYPE EXE SHARED)
      set(VAR CMAKE_${TYPE}_LINKER_FLAGS_${CONFIG}_INIT)
      set(${VAR} "${LDFLAGS}" CACHE STRING "")
      mark_as_advanced(${VAR})
    endforeach()
  endforeach()
endfunction(define_compiler_init_variables)

#-----------------------------------------------------------------------
# Print compiler flags variables
#-----------------------------------------------------------------------
function(print_security_flags_variables)
  foreach(CONFIG DEBUG RELEASE)
    cmake_print_variables(SECURITY_FLAGS_${CONFIG}_LIST)
  endforeach()
endfunction()

function(print_compiler_init_variables LANG)
  foreach(CONFIG ${_COMPILER_FLAGS_CONFIGS})
    cmake_print_variables(CMAKE_${LANG}_FLAGS_${CONFIG}_INIT)
  endforeach()
endfunction()

function(print_compiler_flags_variables LANG)
  foreach(CONFIG ${_COMPILER_FLAGS_CONFIGS})
    cmake_print_variables(CMAKE_${LANG}_FLAGS_${CONFIG})
  endforeach()
endfunction()

#-----------------------------------------------------------------------
# Define variables
#-----------------------------------------------------------------------
define_security_flags_variables()
