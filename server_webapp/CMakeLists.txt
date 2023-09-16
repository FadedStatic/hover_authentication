cmake_minimum_required (VERSION 3.24)
project(server_webapp)

include_directories(libs/argon2/include)
link_directories(libs/argon2)

add_executable(server_webapp main.cpp "database/database.cpp" "auth/auth.cpp"  "scheduler/scheduler.cpp")
set_property(TARGET server_webapp PROPERTY CXX_STANDARD 23)

include(cmake/CPM.cmake)
CPMAddPackage(
    NAME drogon
    VERSION 1.7.5
    GITHUB_REPOSITORY drogonframework/drogon
    GIT_TAG v1.7.5
)


target_link_libraries(${PROJECT_NAME} PRIVATE drogon argon2)