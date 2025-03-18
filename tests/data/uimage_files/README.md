To create a U-Boot/uImage Legacy image:

1. Get a copy of mkimage (such as https://releases.rocketboards.org/release/2020.11/gsrd/tools/mkimage precompiled release for x86_64 Linux)
2. Create a sample data file: `echo "Hello World! This would be the contents of a firmware image." > hello_world`
3. Create the U-Boot/uImage file: `./mkimage -A arm -O linux -T firmware -C none -a 0x1234 -e 0x5678 -n "Test uImage" -d ./hello_world hello_world.img`
