LOCAL_PATH := $(call get_local_path)

PUGIXML_PATH := $(LOCAL_PATH)/pugixml-1.9/scripts
PUGIXML_RELEASE_PATH := $(LOCAL_PATH)/pugixml-1.9/scripts/gmake
PUGIXML_CONF_PATH := $(realpath $(PUGIXML_RELEASE_PATH))/libpugixml.a

include $(CLEAR_VARIABLES)

LOCAL_TARGET := libpugixml.a
LOCAL_PREBUILT_TARGET := $(PUGIXML_RELEASE_PATH)/$(LOCAL_TARGET)
$(LOCAL_PREBUILT_TARGET): $(PUGIXML_CONF_PATH)

include $(BUILD_PREBUILT_LIBRARY)

include $(CLEAR_VARIABLES)

$(PUGIXML_CONF_PATH):
	@cd "$(PUGIXML_PATH)" && make config=release