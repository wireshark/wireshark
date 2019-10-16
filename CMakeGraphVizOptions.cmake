# CMake configuration to control the look and contents of generated graphviz files.
#
# Documentation: https://cmake.org/cmake/help/latest/module/CMakeGraphVizOptions.html
#
# To generate a dependency graph from the build directory:
#
#   cmake . --graphviz=wireshark.dot
#   fdp wireshark.dot -Tpdf -o wireshark.pdf

set(GRAPHVIZ_GRAPH_NAME "Wireshark dependency graph")
set(GRAPHVIZ_GRAPH_HEADER \tsize="5!" \n\tgraph[splines="true",forcelabels="true",overlap="false"] \n)
