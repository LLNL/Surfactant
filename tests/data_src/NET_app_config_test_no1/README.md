
To recreate the exectable file:
1. Create a ConsoleApp project on Visual Studio on a Windows Machine
2. Separately, create a dll file through the Visual Studio C# class library functionality. Compile that
3. Add the dll file as a reference in the Console App project and add it to the list of 'using' statements in the C# file
4. Add an App config file to the project and make sure to include the `<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1"> <\assemblyBinding>` and `<probing privatePath=".\bin\Debug" />` tags.
5. Compile and run
