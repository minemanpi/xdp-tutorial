XDP_TARGETS  := xdp_udp_echo
USER_TARGETS := af_xdp_user 

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

COPY_LOADER := xdp_loader
#COPY_STATS  := xdp_stats
EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h 

include $(COMMON_DIR)/common.mk
LIBS += -lpthread
