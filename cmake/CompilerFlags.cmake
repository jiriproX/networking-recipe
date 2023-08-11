# CompilerFlags.cmake - Set recommended compiler flags.
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

include(CMakePrintHelpers)

option(ENABLE_WARNING_FLAGS "Enable compiler warnings" ON)
option(ENABLE_SPECTRE_FLAGS "Enable Spectre mitigations" ON)

#-----------------------------------------------------------------------
# Get security flags.
#
# Each macro implements a section of the C & C++ Compiler Flag Standards
# in the Intel Secure Coding Standards.
#-----------------------------------------------------------------------
function(_getSecurityFlags mode cflags)

  # Compiler Warnings and Error Detection
  macro(setCompilerWarnings mode cflags)
    if(${mode} STREQUAL "Debug")
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
  macro(setFlowIntegrity mode cflags)
    if(${mode} STREQUAL "Debug")
      list(APPEND ${cflags}
        -fsanitize=cfi
      )
    else()
      list(APPEND ${cflags}
        -flto                 # link-time optimization
        -fsanitize=cfi
        -fvisibility=hidden   # all ELF symbols are hidden by default
      )
    endif()
  endmacro()

  # Format String Defense
  macro(setFormatDefense mode cflags)
    if(${mode} STREQUAL "Debug")
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
  macro(setStackDefense mode cflags)
    if(NOT ${mode} STREQUAL "Debug")
      list(APPEND ${cflags}
        # passed to linker
        # -z noexecstack
        -Wl,-z,noexecstack
      )
    endif()
  endmacro()

  # Position Independent Execution
  macro(setPIE mode cflags)
    list(APPEND ${cflags}
      # passed to compiler
      -fPIE
      # passed to linker
      -pie
    )
  endmacro()

  # Preprocessor Macros
  macro(setFortfy mode cflags)
    list(APPEND ${cflags}
      -D_FORTIFY_FLAGS=2
    )
  endmacro()

  # Read-only Relocation
  macro(setRelocation mode cflags)
    if(NOT ${mode} STREQUAL "Release")
      list(APPEND ${cflags}
        # passed to linker
        -Wl,-z,relro
      )
    endif()
  endmacro()

  # Bounds Check Bypass (Spectre Variant 1)
  macro(setBoundsCheck mode cflags)
    list(APPEND ${cflags}
      -mconditional-branch=keep
      -mconditional-branch=pattern-report
      -mconditonal-branch=pattern-fix
    )
  endmacro()

  # Branch Target Injection (Spectre Variant 2)
  macro(setTargetInjection mode cflags)
    list(APPEND ${cflags}
      -mretpoline
    )
  endmacro()

  set(_cflags)
  set(_mode ${mode})

  if(ENABLE_WARNING_FLAGS)
    setCompilerWarnings(mode _cflags)
  endif()

  setFlowIntegrity(mode _cflags)
  setFormatDefense(mode _cflags)
  setStackDefense(mode _cflags)
  setPIE(mode _cflags)
  setRelocation(mode _cflags)

  if(ENABLE_SPECTRE_FLAGS)
    setBoundsCheck(mode _cflags)
    setTargetInjection(mode _cflags)
  endif()

  list(JOIN _cflags " " _cflags)
  set(${cflags} ${_cflags} PARENT_SCOPE)

endfunction(_getSecurityFlags)

#-----------------------------------------------------------------------
# Define compiler flags.
#-----------------------------------------------------------------------
function(_defineCompilerFlags)

  _getSecurityFlags("Debug" debugFlags)
  _getSecurityFlags("Release" releaseFlags)

  if(DEBUG_COMPILER_FLAGS)
    cmake_print_variables(debugFlags)
    cmake_print_variables(releaseFlags)
    message("")
  endif()

  function(_getVariableName stem mode var)
    string(CONCAT name "CMAKE_" ${stem} "_FLAGS")
    string(TOUPPER "${mode}" MODE)
    if(NOT MODE STREQUAL "")
      string(CONCAT name ${name} "_" ${MODE})
    endif()
    set(${var} "${name}" PARENT_SCOPE)
  endfunction()

  function(_assignVariable stem mode flags)
    _getVariableName("${stem}" "${mode}" var)
    set(value "${${var}}")
    if(NOT value STREQUAL "")
      string(CONCAT ${var} "${value}" " " "${flags}")
    else()
      set(${var} "${flags}")
    endif()
    if(DEBUG_COMPILER_FLAGS)
      cmake_print_variables(${var})
    endif()
  endfunction()

  set(modes Debug MinSizeRel Release RelWithDebInfo)

  foreach(_stem C CXX)
    foreach(_mode ${modes})
      _getVariableName("${_stem}" "${_mode}" var)
      cmake_print_variables(${var})
    endforeach()
    message("")
  endforeach()

  foreach(_stem C CXX)
    foreach(_mode ${modes})
      if(_mode STREQUAL "Debug")
        _assignVariable("${_stem}" "${_mode}" ${debugFlags})
      else()
        _assignVariable("${_stem}" "${_mode}" ${releaseFlags})
      endif()
    endforeach()
    if(DEBUG_COMPILER_FLAGS)
      message("")
    endif()
  endforeach()

endfunction(_defineCompilerFlags)

_defineCompilerFlags()
