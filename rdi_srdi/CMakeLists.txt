set(CMAKE_VERBOSE_MAKEFILE ON)
cmake_minimum_required(VERSION 3.20)
project(loader_project VERSION 0.1.0 LANGUAGES C CXX)

# Standard C++26 (-std=c++26)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
include_directories(${CMAKE_SOURCE_DIR}/src/h)

# Optionnel : Ingestion des objets NASM générés précédemment
set(NASM_NAMES src/nasm/peb)
set(NASM_OBJECTS "")

foreach(src ${NASM_NAMES})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}.asm")
        set(NASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${src}.asm)
        set(NASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${src}.o)
        
        get_filename_component(NASM_OBJ_DIR ${NASM_OBJ} DIRECTORY)
        file(MAKE_DIRECTORY ${NASM_OBJ_DIR})

        add_custom_command(
            OUTPUT ${NASM_OBJ}
            COMMAND nasm -f win64 -o ${NASM_OBJ} ${NASM_SRC}
            DEPENDS ${NASM_SRC}
            COMMENT "Assembling ${NASM_SRC} (win64)..."
        )
        list(APPEND NASM_OBJECTS ${NASM_OBJ})
    endif()
endforeach()

# Déclaration de l'exécutable (CMake ajoutera automatiquement l'extension .exe pour la cible MinGW)
add_executable(loader
    #loader_r.cpp
    loader_srdi.cpp
    #src/c/utils.cpp
    #src/c/ntutils.cpp
    src/c/peb.cpp
    ${NASM_OBJECTS}
)

# Symboles de debug (-g)
target_compile_options(loader PRIVATE
    $<$<CONFIG:Debug>:-g>
)
# target_link_options(loader PRIVATE "-fuse-ld=lld") // agnostique à l'OS >> go CmakePrests.json
# Options de linkage statique (-static -static-libgcc -static-libstdc++)
target_link_options(loader PRIVATE
    -nostdlib
    -nostartfiles
    -nodefaultlibs
    -Wl,-eentry
    -lkernel32
    # -luser32  #
)
# Bibliothèques système Win32 (-luser32 -lkernel32)
target_link_libraries(loader PRIVATE
  
)


# cmake --build "/path/to/build" -- --verbose
# # ou si CMake a généré des Makefiles :
# make VERBOSE=1

