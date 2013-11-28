#
# $Id: 463647aecc57c1c3ee225da9f711cd8d9ed2d6dd $
#
TARGETNAME		:= rlm_prefixpool

ifneq "$(TARGETNAME)" ""
SUBMAKEFILES		:= rlm_prefixpool.mk

# Used by SUBMAKEFILES
rlm_prefixpool_CFLAGS	:=   
rlm_prefixpool_LDLIBS	:= -lgdbm 
endif
