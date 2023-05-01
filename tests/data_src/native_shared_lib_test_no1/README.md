INSTRUCTIONS ON HOW TO BUILD FOR ELF, MACH, AND WINDOWS

To recreate the ELF executable/.so:
- In the directory containing src cpp/hpp files and the CMakeLists.txt, run `cmake -B build/ --install-prefix $PWD/install`
- `cd build/`
- Run `cmake --build .`
- After new files have been generated, run `cmake --install .`
- Then the executable and .so file should have been created.

To recreate the MACH executable/dylib:
- In the directory containing src cpp/hpp files and the CMakeLists.txt, run `cmake -B build/ --install-prefix $PWD/install` in parent directory
- `cd build/`
- Run `cmake --build .`
- After new files have been generated, run`cmake --install .`
- Then the executable and dylib file should have been created.

To recreate the Windows executable and dll file:
- download the cmake-gui on a windows machine
- make sure you have visual studio installed
- follow this tutorial (https://cs184.eecs.berkeley.edu/sp19/article/10/cmake-gui-windows-tutorial) with the CMakeLists.txt and files in the directory
- After configuring and generating, and building the project on Visual Studio, the executable file and the dll should be available in one of the directories.
