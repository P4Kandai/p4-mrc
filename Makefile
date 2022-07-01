BMV2_SWITCH_EXE = simple_switch_grpc

TOPO:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))pod-topo/topology.json
$(warning TOPO = $(TOPO))

include ./utils/Makefile
