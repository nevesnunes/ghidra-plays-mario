#include <SDL2/SDL.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

// BGR565 palette. Used instead of RGBA32 to reduce source code size.
int rgba[64] = {25356, 34816, 39011, 30854, 24714, 4107,  106,   2311,  2468,
                2561,  4642,  6592,  20832, 0,     0,     0,     44373, 49761,
                55593, 51341, 43186, 18675, 434,   654,   4939,  5058,  3074,
                19362, 37667, 0,     0,     0,     ~0,    ~819,  64497, 64342,
                62331, 43932, 23612, 9465,  1429,  1550,  20075, 36358, 52713,
                16904, 0,     0,     ~0,    ~328,  ~422,  ~452,  ~482,  58911,
                50814, 42620, 40667, 40729, 48951, 53078, 61238, 44405},
    scany,    // Scanline Y
    shift_at; // Attribute shift register

uint8_t *rom, *chrrom,                // Points to the start of PRG/CHR ROM
    prg[2], chr[2],                   // Current PRG/CHR banks
    A, X, Y, P = 4, S = ~2, PCH, PCL, // CPU Registers
    addr_lo, addr_hi,                 // Current instruction address
    nomem,     // 1 => current instruction doesn't write to memory
    result,    // Temp variable
    val,       // Current instruction value
    cross,     // 1 => page crossing occurred
    tmp, tmp2, // Temp variables
    ppumask, ppuctrl, ppustatus, // PPU registers
    ppubuf,                      // PPU buffered reads
    W,                           // Write toggle PPU register
    fine_x,                      // X fine scroll offset, 0..7
    opcode,                      // Current instruction opcode
    nmi,                         // 1 => NMI occurred
    ntb,                         // Nametable byte
    ptb_lo, ptb_hi,              // Pattern table low/high byte
    vram[2048],                  // Nametable RAM
    palette_ram[64],             // Palette RAM
    ram[8192],                   // CPU RAM
    chrram[8192],                // CHR RAM (only used for some games)
    prgram[8192],                // PRG RAM (only used for some games)
    oam[256],                    // Object Attribute Memory (sprite RAM)
    mask[] = {128, 64, 1, 2,     // Masks used in branch instructions
              1,   0,  0, 1, 4, 0, 0, 4, 0,
              0,   64, 0, 8, 0, 0, 8}, // Masks used in SE*/CL* instructions.
    keys,                              // Joypad shift register
    mirror,                            // Current mirroring mode
    mmc1_bits, mmc1_data, mmc1_ctrl,   // Mapper 1 (MMC1) registers
    chrbank0, chrbank1, prgbank,       // Current PRG/CHR bank
    rombuf[1024 * 1024],               // Buffer to read ROM file into
    *key_state;

uint16_t T, V,           // "Loopy" PPU registers
    sum,                 // Sum used for ADC/SBC
    dot,                 // Horizontal position of PPU, from 0..340
    atb,                 // Attribute byte
    shift_hi, shift_lo,  // Pattern table shift registers
    cycles,              // Cycle count for current instruction
    frame_buffer[61440]; // 256x240 pixel frame buffer. Top and bottom 8 rows
                         // are not drawn.

#define BUFFER_SIZE 260
uint8_t emusrv_buffer[BUFFER_SIZE];
uint64_t emusrv_keys = 0;
int emusrv_r, emusrv_w;
enum emusrv_proto {
  RUN = 0x01,
  INT = 0x02,
  RAM_R = 0x10,
  RES_R = 0x11,
  RAM_W = 0x12,
  RES_W = 0x13,
  CLT_RAM_R = 0x20,
  CLT_RES_R = 0x21,
  INPUTS_W = 0x30,
  ERR = 0xff
};

void emusrv_read(int n) {
  int code = read(emusrv_r, emusrv_buffer, n);
  if (code == -1) {
		fprintf(stderr, "Cannot read from server: %d %s\n", errno, strerror(errno));
    exit(errno);
  }
  if (code != n) {
		fprintf(stderr, "Did not read enough bytes from server: expected %d, got %d\n", n, code);
    exit(123);
  }
}

void emusrv_ram_r(uint16_t a, uint16_t n) {
  emusrv_buffer[0] = CLT_RAM_R;
  emusrv_buffer[1] = (n & 0xff00) >> 8;
  emusrv_buffer[2] = (n & 0x00ff);
  emusrv_buffer[3] = (a & 0xff00) >> 8;
  emusrv_buffer[4] = (a & 0x00ff);
  write(emusrv_w, emusrv_buffer, 5);
  bzero(emusrv_buffer, BUFFER_SIZE);

  emusrv_read(1);
  switch (emusrv_buffer[0]) {
  case CLT_RES_R:
    emusrv_read(n);
    break;
  default:
    fprintf(stderr, "Unknown req=%02x\n", emusrv_buffer[0]);
    exit(123);
  }
}

void emusrv_step() {
  emusrv_buffer[0] = RUN;
  write(emusrv_w, emusrv_buffer, 1);
  bzero(emusrv_buffer, BUFFER_SIZE);
}

void emusrv_step_dump() {
  emusrv_read(8);
  PCH = emusrv_buffer[0];
  PCL = emusrv_buffer[1];
  A   = emusrv_buffer[2];
  X   = emusrv_buffer[3];
  Y   = emusrv_buffer[4];
  S   = emusrv_buffer[5];
  P   = emusrv_buffer[6];
  cycles = emusrv_buffer[7];
  bzero(emusrv_buffer, BUFFER_SIZE);
  fprintf(stderr, "SRV %02x%02x A:%02x X:%02x Y:%02x S:%02x P:%02x cy=%d\n", PCH, PCL, A, X, Y, S, P, cycles);
  cycles -= 2;
}

void emusrv_nmi() {
  emusrv_buffer[0] = INT;
  write(emusrv_w, emusrv_buffer, 1);
  bzero(emusrv_buffer, BUFFER_SIZE);

  emusrv_step_dump();

  nmi = 0;
}

int emusrv_connect(in_port_t port){
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, fd;

	if((hp = gethostbyname("localhost")) == NULL){
		perror("gethostbyname");
		exit(1);
	}
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(fd == -1){
		perror("setsockopt");
		exit(1);
	}

	if(connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
		perror("connect");
		exit(1);

	}
	return fd;
}

// Read a byte from CHR ROM or CHR RAM.
uint8_t *get_chr_byte(uint16_t a) {
  return &chrrom[chr[a >> 12] << 12 | a & 4095];
}

// Read a byte from nametable RAM.
uint8_t *get_nametable_byte(uint16_t a) {
  return &vram[!mirror       ? a % 1024                  // single bank 0
               : mirror == 1 ? a % 1024 + 1024           // single bank 1
               : mirror == 2 ? a & 2047                  // vertical mirroring
                             : a / 2 & 1024 | a % 1024]; // horizontal mirroring
}

// If `write` is non-zero, writes `val` to the address `hi:lo`, otherwise reads
// a value from the address `hi:lo`.
uint8_t mem(uint8_t lo, uint8_t hi, uint8_t val, uint8_t write) {
  uint16_t a = hi << 8 | lo;

  switch (hi >> 4) {
  case 0 ... 1: // $0000...$1fff RAM
    return write ? ram[a] = val : ram[a];

  case 2 ... 3: // $2000..$2007 PPU (mirrored)
    lo &= 7;

    // read/write $2007
    if (lo == 7) {
      tmp = ppubuf;
      uint8_t *rom =
          // Access CHR ROM or CHR RAM
          V < 8192 ? !write || chrrom == chrram ? get_chr_byte(V) : &tmp2
          // Access nametable RAM
          : V < 16128 ? get_nametable_byte(V)
                      // Access palette RAM
                      : palette_ram + (uint8_t)((V & 19) == 16 ? V ^ 16 : V);
      write ? *rom = val : (ppubuf = *rom);
      V += ppuctrl & 4 ? 32 : 1;
      V %= 16384;
      return tmp;
    }

    if (write)
      switch (lo) {
      case 0: // $2000 ppuctrl
        ppuctrl = val;
        T = T & 62463 | val % 4 << 10;
        break;

      case 1: // $2001 ppumask
        ppumask = val;
        break;

      case 5: // $2005 ppuscroll
        T = (W ^= 1)      ? fine_x = val & 7,
        T & ~31 | val / 8 : T & 35871 | val % 8 << 12 | (val & 248) * 4;
        break;

      case 6: // $2006 ppuaddr
        T = (W ^= 1) ? T & 255 | val % 64 << 8 : (V = T & ~255 | val);
      }

    if (lo == 2) // $2002 ppustatus
      return tmp = ppustatus & 224, ppustatus &= 127, W = 0, tmp;

    break;

  case 4:
    if (write && lo == 20) { // $4014 OAM DMA
      emusrv_ram_r((uint16_t)val << 8, 256);
      for (sum = 256; sum--;) {
        oam[sum] = emusrv_buffer[sum];
      }
      bzero(emusrv_buffer, BUFFER_SIZE);
    }
    // $4016 Joypad 1
    if (lo != 22) {
      return 0;
    } else if (write) {
      if (emusrv_keys != 0) {
        // FIXME: This is a workaround for differentials in instruction counts
        // between when key inputs were recorded, and when they are replayed.
        // A more adequate structure to hold this data would be a FIFO or 
        // ring buffer. Here we are just accounting for the two writes that 
        // set and unset the strobe bit (https://www.nesdev.org/wiki/Controller_reading_code),
        // which always return the same keys value, so the order we are shifting them out 
        // doesn't matter.
        keys = emusrv_keys & 0xff;
        emusrv_keys = emusrv_keys >> 8;
      } else {
        keys = (key_state[SDL_SCANCODE_RIGHT] * 8 +
                key_state[SDL_SCANCODE_LEFT] * 4 +
                key_state[SDL_SCANCODE_DOWN] * 2 +
                key_state[SDL_SCANCODE_UP]) * 16 +
                key_state[SDL_SCANCODE_RETURN] * 8 +
                key_state[SDL_SCANCODE_TAB] * 4 +
                key_state[SDL_SCANCODE_Z] * 2 +
                key_state[SDL_SCANCODE_X];
      }
      return keys;
    } else {
      tmp = keys & 1; keys /= 2; return tmp;
    }

  case 6 ... 7: // $6000...$7fff PRG RAM
    return write ? prgram[a & 8191] = val : prgram[a & 8191];

  case 8 ... 15: // $8000...$ffff ROM
    // handle mmc1 writes
    if (write)
      switch (rombuf[6] >> 4) {
      case 7: // mapper 7
        mirror = !(val / 16);
        *prg = val = val % 8 * 2;
        prg[1] = val + 1;
        break;

      case 3: // mapper 3
        *chr = val = val % 4 * 2;
        chr[1] = val + 1;
        break;

      case 2: // mapper 2
        *prg = val & 31;
        break;

      case 1: // mapper 1
        if (val & 128) {
          mmc1_bits = 5, mmc1_data = 0, mmc1_ctrl |= 12;
        } else if (mmc1_data = mmc1_data / 2 | val << 4 & 16, !--mmc1_bits) {
          mmc1_bits = 5, tmp = a >> 13;
          *(tmp == 4 ? mirror = mmc1_data & 3, &mmc1_ctrl
        : tmp == 5   ? &chrbank0
        : tmp == 6   ? &chrbank1
                     : &prgbank) = mmc1_data;

          // Update CHR banks.
          *chr = chrbank0 & ~!(mmc1_ctrl & 16);
          chr[1] = mmc1_ctrl & 16 ? chrbank1 : chrbank0 | 1;

          // Update PRG banks.
          tmp = mmc1_ctrl / 4 & 3;
          *prg = tmp == 2 ? 0 : tmp == 3 ? prgbank : prgbank & ~1;
          prg[1] = tmp == 2 ? prgbank : tmp == 3 ? rombuf[4] - 1 : prgbank | 1;
        }
      }
    return rom[prg[(a >> 14) - 2] << 14 | a & 16383];
  }

  return ~0;
}

int main(int argc, char **argv) {
  fprintf(stderr, "Connecting to Ghidra...\n");
  emusrv_r = emusrv_connect(6502);
  emusrv_w = emusrv_connect(6502);

  SDL_RWread(SDL_RWFromFile(argv[1], "rb"), rombuf, 1024 * 1024, 1);
  // Start PRG0 after 16-byte header.
  rom = rombuf + 16;
  // PRG1 is the last bank. `rombuf[4]` is the number of 16k PRG banks.
  prg[1] = rombuf[4] - 1;
  // CHR0 ROM is after all PRG data in the file. `rombuf[5]` is the number of
  // 8k CHR banks. If it is zero, assume the game uses CHR RAM.
  chrrom = rombuf[5] ? rom + ((prg[1] + 1) << 14) : chrram;
  // CHR1 is the last 4k bank.
  chr[1] = (rombuf[5] ? rombuf[5] : 1) * 2 - 1;
  // Bit 0 of `rombuf[6]` is 0=>horizontal mirroring, 1=>vertical mirroring.
  mirror = !(rombuf[6] & 1) + 2;

  SDL_Init(SDL_INIT_VIDEO);
  // Create window 1024x840. The framebuffer is 256x240, but we don't draw the
  // top or bottom 8 rows. Scaling up by 4x gives 1024x960, but that looks
  // squished because the NES doesn't have square pixels. So shrink it by 7/8.
  void *renderer = SDL_CreateRenderer(
      SDL_CreateWindow("smolnes", 0, 0, 1024, 840, SDL_WINDOW_SHOWN), -1,
      SDL_RENDERER_PRESENTVSYNC);
  void *texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_BGR565,
                                    SDL_TEXTUREACCESS_STREAMING, 256, 224);
  key_state = (uint8_t*)SDL_GetKeyboardState(0);

  for (;;) {
    cycles = 0;

    if (nmi) {
      emusrv_nmi();
    } else {
      emusrv_step();
      int handle_requests = 1;
      while (handle_requests) {
        emusrv_read(1);
        switch (emusrv_buffer[0]) {
        case RAM_R:
          emusrv_read(2);
          addr_hi = emusrv_buffer[0];
          addr_lo = emusrv_buffer[1];
          result = mem(addr_lo, addr_hi, 0, 0);
          bzero(emusrv_buffer, BUFFER_SIZE);
          emusrv_buffer[0] = RES_R;
          emusrv_buffer[1] = result;
          write(emusrv_w, emusrv_buffer, 2);
          break;
        case RAM_W:
          emusrv_read(3);
          addr_hi = emusrv_buffer[0];
          addr_lo = emusrv_buffer[1];
          result = emusrv_buffer[2];
          mem(addr_lo, addr_hi, result, 1);
          bzero(emusrv_buffer, BUFFER_SIZE);
          emusrv_buffer[0] = RES_W;
          write(emusrv_w, emusrv_buffer, 1);
          break;
        case INPUTS_W:
          emusrv_read(1);
          emusrv_keys = (emusrv_keys << 8) | emusrv_buffer[0];
          break;
        case RUN:
          emusrv_step_dump();
          handle_requests = 0;
          break;
        default:
          fprintf(stderr, "Unknown req=%02x\n", emusrv_buffer[0]);
          exit(123);
        }
        bzero(emusrv_buffer, BUFFER_SIZE);
      }
    }

    // Update PPU, which runs 3 times faster than CPU. Each CPU instruction
    // takes at least 2 cycles.
    for (tmp = cycles * 3 + 6; tmp--;) {
      if (ppumask & 24) { // If background or sprites are enabled.
        if (scany < 240) {
          if (dot < 256 || dot > 319) {
            switch (dot & 7) {
            case 1: // Read nametable byte.
              ntb = *get_nametable_byte(V);
              break;
            case 3: // Read attribute byte.
              atb = (*get_nametable_byte(960 | V & 3072 | V >> 4 & 56 |
                                         V / 4 & 7) >>
                     (V >> 5 & 2 | V / 2 & 1) * 2) &
                    3;
              atb |= atb * 4;
              atb |= atb << 4;
              atb |= atb << 8;
              break;
            case 5: // Read pattern table low byte.
              ptb_lo = *get_chr_byte(ppuctrl << 8 & 4096 | ntb << 4 | V >> 12);
              break;
            case 7: // Read pattern table high byte.
              ptb_hi =
                  *get_chr_byte(ppuctrl << 8 & 4096 | ntb << 4 | V >> 12 | 8);
              // Increment horizontal VRAM read address.
              V = (V & 31) == 31 ? V & ~31 ^ 1024 : V + 1;
              break;
            }

            // Draw a pixel to the framebuffer.
            if ((uint16_t)scany < 240 && dot < 256) {
              // Read color and palette from shift registers.
              uint8_t color = shift_hi >> 14 - fine_x & 2 |
                              shift_lo >> 15 - fine_x & 1,
                      palette = shift_at >> 28 - fine_x * 2 & 12;

              // If sprites are enabled.
              if (ppumask & 16)
                // Loop through all sprites.
                for (uint8_t *sprite = oam; sprite < oam + 256; sprite += 4) {
                  uint16_t sprite_h = ppuctrl & 32 ? 16 : 8,
                           sprite_x = dot - sprite[3],
                           sprite_y = scany - *sprite - 1,
                           sx = sprite_x ^ (sprite[2] & 64 ? 0 : 7),
                           sy = sprite_y ^ (sprite[2] & 128 ? sprite_h - 1 : 0);
                  if (sprite_x < 8 && sprite_y < sprite_h) {
                    uint16_t sprite_tile = sprite[1],
                             sprite_addr = ppuctrl & 32
                                               // 8x16 sprites
                                               ? sprite_tile % 2 << 12 |
                                                     (sprite_tile & ~1) << 4 |
                                                     (sy & 8) * 2 | sy & 7
                                               // 8x8 sprites
                                               : (ppuctrl & 8) << 9 |
                                                     sprite_tile << 4 | sy & 7,
                             sprite_color =
                                 *get_chr_byte(sprite_addr + 8) >> sx << 1 & 2 |
                                 *get_chr_byte(sprite_addr) >> sx & 1;
                    // Only draw sprite if color is not 0 (transparent)
                    if (sprite_color) {
                      // Don't draw sprite if BG has priority.
                      !(sprite[2] & 32 && color)
                          ? color = sprite_color,
                            palette = 16 | sprite[2] * 4 & 12 : 0;
                      // Maybe set sprite0 hit flag.
                      sprite == oam &&color ? ppustatus |= 64 : 0;
                      break;
                    }
                  }
                }

              // Write pixel to framebuffer. Always use palette 0 for color 0.
              frame_buffer[scany * 256 + dot] =
                  rgba[palette_ram[color ? palette | color : 0]];
            }

            // Update shift registers every cycle.
            dot < 336 ? shift_hi *= 2, shift_lo *= 2, shift_at *= 4 : 0;

            // Reload shift registers every 8 cycles.
            dot % 8 == 7        ? shift_hi |= ptb_hi, shift_lo |= ptb_lo,
                shift_at |= atb : 0;
          }

          // Increment vertical VRAM address.
          dot == 256 ? V = ((V & 7 << 12) != 7 << 12 ? V + 4096
                            : (V & 992) == 928       ? V & 35871 ^ 2048
                            : (V & 992) == 992       ? V & 35871
                                               : V & 35871 | V + 32 & 992) &
                               // Reset horizontal VRAM address to T value.
                               ~1055 |
                           T & 1055
                     : 0;
        }

        // Reset vertical VRAM address to T value.
        scany == -1 &&dot > 279 &&dot < 305 ? V = V & 33823 | T & 31712 : 0;
      }

      if (scany == 241 && dot == 1) {
        // If NMI is enabled, trigger NMI.
        ppuctrl & 128 ? nmi = 1 : 0;
        ppustatus |= 128;
        // Render frame, skipping the top and bottom 8 pixels (they're often
        // garbage).
        SDL_UpdateTexture(texture, 0, frame_buffer + 2048, 512);
        SDL_RenderCopy(renderer, texture, 0, 0);
        SDL_RenderPresent(renderer);
        // Handle SDL events.
        for (SDL_Event event; SDL_PollEvent(&event);)
          if (event.type == SDL_QUIT)
            return 0;
      }

      // Clear ppustatus.
      scany == -1 &&dot == 1 ? ppustatus = 0 : 0;

      // Increment to next dot/scany. 341 dots per scanline, 262 scanlines per
      // frame. Scanline 261 is represented as -1.
      ++dot == 341 ? dot = 0, scany = scany == 260 ? -1 : scany + 1 : 0;
    }
  }
}
// vim: ts=2 sw=2 sts=2
