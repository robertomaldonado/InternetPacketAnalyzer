#!/bin/sh
rm tests/noOpt/rob_out.* tests/bigV/rob_out.* tests/smallV/rob_out.*
rm tests/noOpt/diffs.txt tests/bigV/diffs.txt tests/smallV/diffs.txt
make all

# Test the files with option -V enabled
./parser3 dumpfile.3 > tests/noOpt/rob_out.3
./parser3 dumpfile.200 > tests/noOpt/rob_out.200
./parser3 dumpfile.500 > tests/noOpt/rob_out.500
./parser3 dumpfile.5000 > tests/noOpt/rob_out.5000

diff tests/noOpt/m_out.3 tests/noOpt/rob_out.3 >> tests/noOpt/diffs.txt
diff tests/noOpt/m_out.200 tests/noOpt/rob_out.200 >> tests/noOpt/diffs.txt
diff tests/noOpt/m_out.500 tests/noOpt/rob_out.500 >> tests/noOpt/diffs.txt
diff tests/noOpt/m_out.5000 tests/noOpt/rob_out.5000 >> tests/noOpt/diffs.txt

# Test the files with option -v enabled
./parser3 dumpfile.3 -v > tests/smallV/rob_out.3
./parser3 dumpfile.200 -v > tests/smallV/rob_out.200
./parser3 dumpfile.500 -v > tests/smallV/rob_out.500
./parser3 dumpfile.5000 -v > tests/smallV/rob_out.5000

diff tests/smallV/m_out.3 tests/smallV/rob_out.3 >> tests/smallV/diffs.txt
diff tests/smallV/m_out.200 tests/smallV/rob_out.200 >> tests/smallV/diffs.txt
diff tests/smallV/m_out.500 tests/smallV/rob_out.500 >> tests/smallV/diffs.txt
diff tests/smallV/m_out.5000 tests/smallV/rob_out.5000 >> tests/smallV/diffs.txt

# Test the files with option -V enabled
./parser3 dumpfile.3 -V > tests/bigV/rob_out.3
./parser3 dumpfile.200 -V > tests/bigV/rob_out.200
./parser3 dumpfile.500 -V > tests/bigV/rob_out.500
./parser3 dumpfile.5000 -V > tests/bigV/rob_out.5000

diff tests/bigV/m_out.3 tests/bigV/rob_out.3 >> tests/bigV/diffs.txt
diff tests/bigV/m_out.200 tests/bigV/rob_out.200 >> tests/bigV/diffs.txt
diff tests/bigV/m_out.500 tests/bigV/rob_out.500 >> tests/bigV/diffs.txt
diff tests/bigV/m_out.5000 tests/bigV/rob_out.5000 >> tests/bigV/diffs.txt


