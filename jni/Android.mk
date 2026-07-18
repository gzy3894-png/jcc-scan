LOCAL_PATH := $(call my-dir)

# ---- 扫描 SO：注入游戏进程 ----
include $(CLEAR_VARS)
LOCAL_MODULE := JCC
LOCAL_SRC_FILES := \
    src/scan_payload.c \
    xdl/xdl.c \
    xdl/xdl_iterate.c \
    xdl/xdl_linker.c \
    xdl/xdl_lzma.c \
    xdl/xdl_util.c
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/xdl/include
# 保留默认可见，确保 constructor / JNI_OnLoad / jcc_scan_entry 不被裁掉
LOCAL_CFLAGS := -O2 -DANDROID -Wall -fno-emulated-tls
LOCAL_LDFLAGS := -Wl,--export-dynamic
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

# ---- 可执行文件：用户 root 运行 ----
include $(CLEAR_VARS)
LOCAL_MODULE := jcc-scan
LOCAL_SRC_FILES := src/main.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -O2 -Wall -DANDROID
include $(BUILD_EXECUTABLE)
