
TEENSY = 36
INO_FILES = atecc_lib.ino

ifdef FEATHER
FEATHER_LIBS = SPI Wire
else
TEENSY_LIBS = SPI Entropy
TEENSY_LIBS += Wire EEPROM
#TEENSY_LIBS += i2c_t3
#LIB_DIRS += /Volumes/Devel/crypto/atecc_lib/Wire
endif
TEENSY_LIBS += Time

LIB_DIRS += /Volumes/Devel/crypto/WolfSSLClient
LIB_DIRS += /Volumes/Devel/crypto/AtCryptoAuthLib
LIB_DIRS += /Volumes/Devel/crypto/WolfCryptoAuth
LIB_DIRS += /Volumes/Devel/Projects/Readline

EXTRA_DEFINES = ATCAPRINTF ATCA_HAL_I2C __arm__
#EXTRA_DEFINES += LIB_DEBUG
EXTRA_DEFINES += USE_WOLFSSL
EXTRA_DEFINES += USE_EEPROM
#EXTRA_DEFINES += DEBUG_I2C

ifndef NO_WIFI
LIB_DIRS += /Volumes/Devel/Arduino/WiFi101/src
EXTRA_DEFINES += USE_WIFI
endif

ifdef FEATHER
SERIAL_PORT = cu.usbmodem141121
include /Volumes/Devel/samd/feather.mk
else
EXTRA_DEFINES += CORE_TEENSY
include /Volumes/Devel/teensy/teensy.mk
endif

