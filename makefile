#for INTEST GDENGINE & SPI AG35
USR_LIB=$(SDKTARGETSYSROOT)/usr/lib/libql_peripheral.a

TARGET_GD_SE_TEST=gd_se_test

CFLAGS=-w -c -fPIC -O2 -DENGINE_DYNAMIC_SUPPORT -DSPI

CPPFLAGS += -I./                                            \
            -Ilibgd/                                        \
            -I$(SDKTARGETSYSROOT)/usr/include               \
            -I$(SDKTARGETSYSROOT)/usr/include/openssl       \
            -I$(SDKTARGETSYSROOT)/usr/include/data          \
            -I$(SDKTARGETSYSROOT)/usr/include/dsutils       \
            -I$(SDKTARGETSYSROOT)/usr/include/qmi           \
            -I$(SDKTARGETSYSROOT)/usr/include/qmi-framework \
            -I$(SDKTARGETSYSROOT)/usr/include/quectel-openlinux-sdk

ALL_LINKS = -L$(SDKTARGETSYSROOT)/usr/lib -L$(SDKTARGETSYSROOT)/lib

LD_FLAGS = -ldsi_netctrl \
    -lqdi \
    -lqmi_client_helper \
    -lqmi -lqmiservices -lqmi_client_qmux -lqmiidl \
    -lqmi_csi -lqmi_common_so -lqmi_cci -lqmi_sap -lqmi_encdec \
    -lnetmgr -lrmnetctl -ldiag -lconfigdb -lxml -ldsutils \
    -ltime_genoff -lgthread-2.0 -lglib-2.0 \
    -lpthread -lcrypto -lssl

OBJ_DIR=objs
EXE_DIR=output

USER_LINK=-L. -Llibgd/ -lGDEngine -lsehal

SRC_GD_SE_TEST=gd_se_test.cc

all:prep $(EXE_DIR)/$(TARGET_GD_SE_TEST)

prep:
	@if test ! -d $(OBJ_DIR); then mkdir $(OBJ_DIR); fi
	@if test ! -d $(EXE_DIR); then mkdir $(EXE_DIR); fi

## Build CS test
$(EXE_DIR)/$(TARGET_GD_SE_TEST):$(SRC_GD_SE_TEST)
	@echo --------------------------
	@echo Compile Client $(EXE_DIR)/$(TARGET_GD_SE_TEST), from $(SRC_GD_SE_TEST)
	@$(CXX) -o $(EXE_DIR)/$(TARGET_GD_SE_TEST) -w -fPIC -O2 $(SRC_GD_SE_TEST) $(CPPFLAGS) $(LD_FLAGS) $(USER_LINK) $(USR_LIB) -std=c++11
	@echo --------------------------

.PHONY:clean
clean:
	rm -rf $(EXE_DIR)/* $(OBJ_DIR) $(EXE_DIR)
