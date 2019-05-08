#!/bin/sh
# File:   testAll.sh
# Author: Roberto Maldonado

# Description: Automate some testing outputs

#Erase previous existing files
rm -r tests

#Recompile
make all

#Create directories
mkdir tests/
mkdir tests/noOpt
mkdir tests/smallV
mkdir tests/bigV

# Test the files with no option enabled
./packetInspector Dumpfiles/dumpfile.3 > tests/noOpt/output.3
./packetInspector Dumpfiles/dumpfile.200 > tests/noOpt/output.200
./packetInspector Dumpfiles/dumpfile.500 > tests/noOpt/output.500

# Test the files with option -v enabled
./packetInspector Dumpfiles/dumpfile.3 -v > tests/smallV/output.3
./packetInspector Dumpfiles/dumpfile.200 -v > tests/smallV/output.200
./packetInspector Dumpfiles/dumpfile.500 -v > tests/smallV/output.500

# Test the files with option -V enabled
./packetInspector Dumpfiles/dumpfile.3 -V > tests/bigV/output.3
./packetInspector Dumpfiles/dumpfile.200 -V > tests/bigV/output.200
./packetInspector Dumpfiles/dumpfile.500 -V > tests/bigV/output.500

