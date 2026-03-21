CC      = cl
CFLAGS  = /W4 /WX /std:c17 /Zi /nologo \
          /I"C:\npcap-sdk-1.16\Include"
LDFLAGS = /nologo \
          /LIBPATH:"C:\npcap-sdk-1.16\Lib\x64" \
          wpcap.lib \
          Packet.lib \
          ws2_32.lib \
          iphlpapi.lib \
          crypt32.lib \
          advapi32.lib

SRCS    = src\main.c src\capture.c src\analyser.c \
          src\server.c src\dns_cache.c
OUT     = netscope.exe
HTML_H  = include\dashboard_html.h

all: $(HTML_H) $(OUT)

$(HTML_H):
	python tools\embed_html.py

$(OUT): $(SRCS) $(HTML_H)
	$(CC) $(CFLAGS) $(SRCS) /Fe:$(OUT) /link $(LDFLAGS)

clean:
	del /Q *.exe *.obj *.pdb 2>nul
	del /Q include\dashboard_html.h 2>nul

.PHONY: all clean