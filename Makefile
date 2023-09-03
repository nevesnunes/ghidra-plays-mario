.PHONY: all clean
all: smolnes_emuclt smolnes_standalone

WARN=-Wall \
     -Wno-parentheses \
		 -Wno-misleading-indentation \
		 -Wno-bool-operation \
		 -Wno-discarded-qualifiers \
		 -Wno-incompatible-pointer-types-discards-qualifiers \
		 -Wno-unknown-warning-option

smolnes_emuclt: smolnes_emuclt.c
	$(CC) -O2 -o $@ $< -lSDL2 -g ${WARN}

smolnes_standalone: smolnes_standalone.c
	$(CC) -O2 -o $@ $< -lSDL2 -g ${WARN}

clean:
	rm -f smolnes_emuclt smolnes_standalone
