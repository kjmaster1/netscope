CC      = cl
CFLAGS  = /W4 /WX /std:c17 /Zi /nologo \
          /I"C:\npcap-sdk-1.16\Include"
LDFLAGS = /nologo \
          /LIBPATH:"C:\npcap-sdk-1.16\Lib\x64" \
          wpcap.lib \
          Packet.lib \
          ws2_32.lib \
          iphlpapi.lib

SRCS    = src\main.c src\capture.c src\analyser.c src\server.c
OUT     = netscope.exe

all: $(OUT)

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) /Fe:$(OUT) /link $(LDFLAGS)

clean:
	del /Q *.exe *.obj *.pdb 2>nul

.PHONY: all clean