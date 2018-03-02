LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := pic32prog
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	hidapi/hid-libusb.c \
	pic32prog.c \
	target.c \
	executive.c \
	adapter-hidboot.c \
	adapter-an1388.c \
	family-mx1.c \
	family-mx3.c \
	family-mz.c

LOCAL_C_INCLUDES = \
	$(LOCAL_PATH)/hidapi \
	$(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include

LOCAL_SHARED_LIBRARIES := liblog libusb

# Include backported features from a newer version of bionic
LOCAL_SHARED_LIBRARIES += libcfuture

LOCAL_CFLAGS := -DVERSION='"2.0 + VDK modifications"' -Wno-format-security -Wno-unused-parameter -Wno-sign-compare

# Depend on kernel headers
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr

include $(BUILD_EXECUTABLE)
