THEOS_DEVICE_IP = 0.0.0.0
ARCHS = arm64
TARGET = iphone:clang:16.5:14.0

TWEAK_NAME = seilahxdja

seilahxdja_FILES = Tweak.mm SeilahAuth.mm
seilahxdja_FRAMEWORKS = UIKit Foundation Security
seilahxdja_CFLAGS = -fobjc-arc
seilahxdja_LDFLAGS = -install_name @executable_path/rosauthhook.dylib

include $(THEOS)/makefiles/tweak.mk
