- OLE/MSI file
	- msitest_no1
		- A compiled C++ Program where wixl was used to create an msi file that contains the executable
		- files:
			- hello.cpp
			- hello.exe
			- test.wxs
			- README.md
	-
-   .NET files
	-	NET_app_config_test_no1
		- A C# Program that includes a dependency referenced in the app config file
		- files:
			- App.config
			- ConsoleApp2.csproj
			- ConsoleApp2.sln
			- Program.cs
			- hello.cs
			- hello.csproj
			- hello.sln
			- README.md


-   PE files /  ELF files / MACH-O files
	- (include at least one exe and dll where the exe should use the dll; include a case with a matching dll name but in the wrong folder so it won't be loaded)
		- native_shared_lib_test_no1
			- A C++ Program that uses a shared library was compiled to create an executable file.
			- files:
				- lib/testlib.cpp
				- lib/testlib.hpp
				- CMakeLists.txt
				- hello_world.cpp
				- README.md (contains instructions on how to build files with the same CMakeLists.txt)


-   Intel Hex and Motorola S-Record files
	- srectest_no1
		- files:
			- BinaryFile.bin
			- HexFile.hex
			- README.md


-   Java class file(s) with a set of known imports
	- Java hello world program
	- java_class_no1
		- files:
			- Helloworld.class
			- HelloWorld.jar
			- helloworld.java
			- README.md
