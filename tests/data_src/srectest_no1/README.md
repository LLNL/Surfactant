To recreate these files:
1. `head -c 100 < /dev/urandom > BinaryFile.bin` create binary file
2. `srec_cat BinaryFile.bin -Binary -o HexFile.hex -Motorola` to create srec file HexFile.hex
