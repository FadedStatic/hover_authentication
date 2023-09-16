# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.24)

project ("hover_auth")

# Include sub-projects.
add_subdirectory ("server_webapp")
