/*
 * Flash memory programmer for Microchip PIC32 microcontrollers.
 *
 * Copyright (C) 2011-2014 Serge Vakulenko
 *
 * This file is part of PIC32PROG project, which is distributed
 * under the terms of the GNU General Public License (GPL).
 * See the accompanying file "COPYING" for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <libgen.h>
#include <locale.h>

#include "target.h"
#include "localize.h"
#include "hidapi/hidapi.h"

#ifndef VERSION
#define VERSION         "2.0."SVNVERSION
#endif
#define MINBLOCKSZ      128
#define FLASHV_BASE     0x9d000000
#define BOOTV_BASE      0x9fc00000
#define FLASHP_BASE     0x1d000000
#define BOOTP_BASE      0x1fc00000
#define FLASH_BYTES     (2048 * 1024)
#define BOOT_BYTES      (80 * 1024)

/* Macros for converting between hex and binary. */
#define NIBBLE(x)       (isdigit(x) ? (x)-'0' : tolower(x)+10-'a')
#define HEX(buffer)     ((NIBBLE((buffer)[0])<<4) + NIBBLE((buffer)[1]))

/* Data to write */
unsigned char boot_data [BOOT_BYTES];
unsigned char flash_data [FLASH_BYTES];
unsigned char boot_dirty [BOOT_BYTES / MINBLOCKSZ];
unsigned char flash_dirty [FLASH_BYTES / MINBLOCKSZ];
unsigned blocksz;               /* Size of flash memory block */
unsigned boot_used;
unsigned flash_used;
unsigned boot_bytes;
unsigned flash_bytes;
unsigned devcfg_offset;         /* Offset of devcfg registers in boot data */
int total_bytes;
unsigned short gFlashChecksum = 0;

#if 0
FILE *fp;
#endif

#define devcfg3 (*(unsigned*) &boot_data [devcfg_offset])
#define devcfg2 (*(unsigned*) &boot_data [devcfg_offset + 4])
#define devcfg1 (*(unsigned*) &boot_data [devcfg_offset + 8])
#define devcfg0 (*(unsigned*) &boot_data [devcfg_offset + 12])

unsigned progress_count;
int verify_only;
int skip_verify = 0;
int debug_level;
int power_on;
target_t *target;
const char *target_port;        /* Optional name of target serial port */
char *progname;
const char *copyright;

void *fix_time ()
{
    static struct timeval t0;

    gettimeofday (&t0, 0);
    return &t0;
}

unsigned mseconds_elapsed (void *arg)
{
    struct timeval t1, *t0 = arg;
    unsigned mseconds;

    gettimeofday (&t1, 0);
    mseconds = (t1.tv_sec - t0->tv_sec) * 1000 +
        (t1.tv_usec - t0->tv_usec) / 1000;
    if (mseconds < 1)
        mseconds = 1;
    return mseconds;
}

void store_data (unsigned address, unsigned byte)
{
    unsigned offset;

    if (address >= BOOTV_BASE && address < BOOTV_BASE + BOOT_BYTES) {
        /* Boot code, virtual. */
        offset = address - BOOTV_BASE;
        boot_data [offset] = byte;
        boot_used = 1;

    } else if (address >= BOOTP_BASE && address < BOOTP_BASE + BOOT_BYTES) {
        /* Boot code, physical. */
        offset = address - BOOTP_BASE;
        boot_data [offset] = byte;
        boot_used = 1;

    } else if (address >= FLASHV_BASE && address < FLASHV_BASE + FLASH_BYTES) {
        /* Main flash memory, virtual. */
        offset = address - FLASHV_BASE;
        flash_data [offset] = byte;
        flash_used = 1;
#if 0      
        if (offset%4 == 0)
        {
            fprintf(fp, "0x%X :", address );
        }
        fprintf(fp, "0x%X ", flash_data[offset]);
        if (offset%4 == 3)
        {
            fprintf(fp, "\n");
        }
#endif 

    } else if (address >= FLASHP_BASE && address < FLASHP_BASE + FLASH_BYTES) {
        /* Main flash memory, physical. */
        offset = address - FLASHP_BASE;
        flash_data [offset] = byte;
        flash_used = 1;
#if 0
        if (offset%4 == 0)
        {
            fprintf(fp, "0x%X :", address );
        }
        fprintf(fp, "0x%X ", flash_data[offset]);
        if (offset%4 == 3)
        {
            fprintf(fp, "\n");
        }
#endif 
 
    } else {
        /* Ignore incorrect data. */
#if DO_DEBUG_PRINTS
        //fprintf (stderr, _("%08X: address out of flash memory\n"), address);
#endif
        return;
    }
    total_bytes++;
}

/*
 * Read the S record file.
 */
int read_srec (char *filename)
{
    FILE *fd;
    unsigned char buf [256];
    unsigned char *data;
    unsigned address;
    int bytes;

    fd = fopen (filename, "r");
    if (! fd) {
        perror (filename);
        exit (1);
    }
    while (fgets ((char*) buf, sizeof(buf), fd)) {
        if (buf[0] == '\n')
            continue;
        if (buf[0] != 'S') {
            fclose (fd);
            return 0;
        }
        if (buf[1] == '7' || buf[1] == '8' || buf[1] == '9')
            break;

        /* Starting an S-record.  */
        if (! isxdigit (buf[2]) || ! isxdigit (buf[3])) {
#if DO_DEBUG_PRINTS
            fprintf (stderr, _("%s: bad SREC record: %s\n"), filename, buf);
#endif
            exit (1);
        }
        bytes = HEX (buf + 2);

        /* Ignore the checksum byte.  */
        --bytes;

        address = 0;
        data = buf + 4;
        switch (buf[1]) {
        case '3':
            address = HEX (data);
            data += 2;
            --bytes;
            /* Fall through.  */
        case '2':
            address = (address << 8) | HEX (data);
            data += 2;
            --bytes;
            /* Fall through.  */
        case '1':
            address = (address << 8) | HEX (data);
            data += 2;
            address = (address << 8) | HEX (data);
            data += 2;
            bytes -= 2;

            while (bytes-- > 0) {
                store_data (address++, HEX (data));
                data += 2;
            }
            break;
        }
    }
    fclose (fd);
    return 1;
}

static const unsigned int crc15Table[256] = {

    0x0,0xc599, 0xceab, 0xb32, 0xd8cf, 0x1d56, 0x1664, 0xd3fd, 0xf407, 0x319e, 0x3aac,  //!<precomputed CRC15 Table

    0xff35, 0x2cc8, 0xe951, 0xe263, 0x27fa, 0xad97, 0x680e, 0x633c, 0xa6a5, 0x7558, 0xb0c1,

    0xbbf3, 0x7e6a, 0x5990, 0x9c09, 0x973b, 0x52a2, 0x815f, 0x44c6, 0x4ff4, 0x8a6d, 0x5b2e,

    0x9eb7, 0x9585, 0x501c, 0x83e1, 0x4678, 0x4d4a, 0x88d3, 0xaf29, 0x6ab0, 0x6182, 0xa41b,

    0x77e6, 0xb27f, 0xb94d, 0x7cd4, 0xf6b9, 0x3320, 0x3812, 0xfd8b, 0x2e76, 0xebef, 0xe0dd,

    0x2544, 0x2be, 0xc727, 0xcc15, 0x98c, 0xda71, 0x1fe8, 0x14da, 0xd143, 0xf3c5, 0x365c,

    0x3d6e, 0xf8f7,0x2b0a, 0xee93, 0xe5a1, 0x2038, 0x7c2, 0xc25b, 0xc969, 0xcf0, 0xdf0d,

    0x1a94, 0x11a6, 0xd43f, 0x5e52, 0x9bcb, 0x90f9, 0x5560, 0x869d, 0x4304, 0x4836, 0x8daf,

    0xaa55, 0x6fcc, 0x64fe, 0xa167, 0x729a, 0xb703, 0xbc31, 0x79a8, 0xa8eb, 0x6d72, 0x6640,

    0xa3d9, 0x7024, 0xb5bd, 0xbe8f, 0x7b16, 0x5cec, 0x9975, 0x9247, 0x57de, 0x8423, 0x41ba,

    0x4a88, 0x8f11, 0x57c, 0xc0e5, 0xcbd7, 0xe4e, 0xddb3, 0x182a, 0x1318, 0xd681, 0xf17b,

    0x34e2, 0x3fd0, 0xfa49, 0x29b4, 0xec2d, 0xe71f, 0x2286, 0xa213, 0x678a, 0x6cb8, 0xa921,

    0x7adc, 0xbf45, 0xb477, 0x71ee, 0x5614, 0x938d, 0x98bf, 0x5d26, 0x8edb, 0x4b42, 0x4070,

    0x85e9, 0xf84, 0xca1d, 0xc12f, 0x4b6, 0xd74b, 0x12d2, 0x19e0, 0xdc79, 0xfb83, 0x3e1a, 0x3528,

    0xf0b1, 0x234c, 0xe6d5, 0xede7, 0x287e, 0xf93d, 0x3ca4, 0x3796, 0xf20f, 0x21f2, 0xe46b, 0xef59,

    0x2ac0, 0xd3a, 0xc8a3, 0xc391, 0x608, 0xd5f5, 0x106c, 0x1b5e, 0xdec7, 0x54aa, 0x9133, 0x9a01,

    0x5f98, 0x8c65, 0x49fc, 0x42ce, 0x8757, 0xa0ad, 0x6534, 0x6e06, 0xab9f, 0x7862, 0xbdfb, 0xb6c9,

    0x7350, 0x51d6, 0x944f, 0x9f7d, 0x5ae4, 0x8919, 0x4c80, 0x47b2, 0x822b, 0xa5d1, 0x6048, 0x6b7a,

    0xaee3, 0x7d1e, 0xb887, 0xb3b5, 0x762c, 0xfc41, 0x39d8, 0x32ea, 0xf773, 0x248e, 0xe117, 0xea25,

    0x2fbc, 0x846, 0xcddf, 0xc6ed, 0x374, 0xd089, 0x1510, 0x1e22, 0xdbbb, 0xaf8, 0xcf61, 0xc453,

    0x1ca, 0xd237, 0x17ae, 0x1c9c, 0xd905, 0xfeff, 0x3b66, 0x3054, 0xf5cd, 0x2630, 0xe3a9, 0xe89b,

    0x2d02, 0xa76f, 0x62f6, 0x69c4, 0xac5d, 0x7fa0, 0xba39, 0xb10b, 0x7492, 0x5368, 0x96f1, 0x9dc3,

    0x585a, 0x8ba7, 0x4e3e, 0x450c, 0x8095

};



unsigned short compute_checksum(unsigned long len, unsigned char *data1)

{

    unsigned short remainder,addr;

    unsigned long i = 0;



    remainder = 16;//initialize the PEC

    for (i = 0; i<len; i++) // loops for each byte in data array

    {

        addr = ((remainder>>7)^data1[i])&0xff;//calculate PEC table address

        remainder = (remainder<<8)^crc15Table[addr];

    }

    return(remainder*2);//The CRC15 has a 0 in the LSB so the remainder must be multiplied by 2

}

int read_bin (char *filename)
{
    FILE *fbin;
#if 0
    FILE *ftmp;
#endif
    char checksum_str[3];
    char bin_data[2];
    char bin_data_str[3];
    int i=0;
    int offset = 0;
    unsigned short checksum_comp = 0;
#if 0
    printf("Entered read_bin\n");
    ftmp = fopen("/home/ems/Data_Files/read_data7.txt", "w");
#endif

    fbin = fopen(filename, "r");
    if (!fbin)
    {
        perror(filename);
        exit(1);
    }

    fgets((char *) checksum_str, sizeof(checksum_str), fbin);
    
    gFlashChecksum = (unsigned short) ( (((checksum_str[0] & 0xF0) >> 4) << 12) | (((checksum_str[0] & 0x0F) ) << 8) |
                                        (checksum_str[1] & 0xF0)  | (checksum_str[1] & 0x0F) );



#if 0
    fprintf(ftmp, "Checksum From Bin File: %X\n", gFlashChecksum);
#endif

    while(fgets((char *) bin_data, sizeof(bin_data), fbin))
    {
         flash_data[offset] = (unsigned char)  bin_data[0];
#if 0
         fprintf(ftmp, "flash_data[%d] = %02X\n", offset, flash_data[offset]);
#endif
         offset++;
    }
    flash_used = 1;
    checksum_comp = compute_checksum(FLASH_BYTES, flash_data);
#if 0
    printf("checksum_comp : %04X\n", checksum_comp);
    printf("gFlashChecksum : %04X\n", gFlashChecksum);
#endif
    if (gFlashChecksum != checksum_comp)
    {
        printf("Error: Invalid checksum. Bin file corrupted.\n");
        printf("Firmware download aborted.\n");
        exit(1);
    }
    fclose(fbin);
#if 0
    fclose(ftmp);
    printf("Exiting read_bin\n");
#endif
    return 1;
}


void print_symbols (char symbol, int cnt)
{
    while (cnt-- > 0)
        putchar (symbol);
}

void progress (unsigned step)
{
    ++progress_count;
    if (progress_count % step == 0) {
        putchar ('#');
        fflush (stdout);
    }
}

void quit (void)
{
    //fprintf(stderr, "Calling quit\n");
    if (target != 0) {
        target_close (target, power_on);
        free (target);
        target = 0;
    }
    printf("\n");
}

void interrupted (int signum)
{
#if DO_DEBUG_PRINTS
    fprintf (stderr, _("\nInterrupted.\n"));
#endif
    quit();
    _exit (-1);
}

/*
 * Check that the boot block, containing devcfg registers,
 * has some useful data.
 */
static int is_flash_block_dirty (unsigned offset)
{
    int i;

    for (i=0; i<blocksz; i++, offset++) {
        if (flash_data [offset] != 0xff)
            return 1;
    }
    return 0;
}

/*
 * Check that the boot block, containing devcfg registers,
 * has some other data.
 */
static int is_boot_block_dirty (unsigned offset)
{
    int i;

    for (i=0; i<blocksz; i++, offset++) {
        /* Skip devcfg registers. */
        if (offset >= devcfg_offset && offset < devcfg_offset+16)
            continue;
        if (boot_data [offset] != 0xff)
            return 1;
    }
    return 0;
}

void do_probe ()
{
    /* Open and detect the device. */
    atexit (quit);
    target = target_open (target_port);
    if (! target) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, _("Error detecting device -- check cable!\n"));
#endif
        exit (1);
    }
    boot_bytes = target_boot_bytes (target);
    printf (_("    Processor: %s (id %08X)\n"), target_cpu_name (target),
        target_idcode (target));
    printf (_(" Flash memory: %d kbytes\n"), target_flash_bytes (target) / 1024);
    if (boot_bytes > 0)
        printf (_("  Boot memory: %d kbytes\n"), boot_bytes / 1024);
    target_print_devcfg (target);
}

/*
 * Write flash memory.
 */
void program_block (target_t *mc, unsigned addr, int cmd_location)
{
    unsigned char *data;
    unsigned offset;

    if (addr >= BOOTV_BASE && addr < BOOTV_BASE + boot_bytes) {
        data = boot_data;
        offset = addr - BOOTV_BASE;
    } else if (addr >= BOOTP_BASE && addr < BOOTP_BASE + boot_bytes) {
        data = boot_data;
        offset = addr - BOOTP_BASE;
    } else if (addr >= FLASHV_BASE && addr < FLASHV_BASE + flash_bytes) {
        data = flash_data;
        offset = addr - FLASHV_BASE;
    } else {
        data = flash_data;
        offset = addr - FLASHP_BASE;
    }
#if DO_DEBUG_PRINTS
    //fprintf(stderr, "Calling target_program_block\n");
#endif
#if 0
    //if (( addr >= 0x1d03F400) && (addr < 0x1d040000))
    {
        int ctr = 0;
        int lp = 0;
        for (ctr = 0; ctr < (blocksz); ctr++)
        {
            //if ( ((offset+ctr) >= 0x3F580) && ((offset+ctr) <= 0x3F59C))
            {
            if (lp%16 == 0)
               fprintf(fp, " 0x%X: \n", (offset+ctr));
            fprintf(fp, "0x%X ", (unsigned *) *(data+offset+ctr));
            lp++;
            }
        } 
    }
#endif
    target_program_block (mc, addr, blocksz/4, (unsigned*) (data + offset), cmd_location);
}

int verify_block (target_t *mc, unsigned addr)
{
    unsigned char *data;
    unsigned offset;

    if (addr >= BOOTV_BASE && addr < BOOTV_BASE + boot_bytes) {
        data = boot_data;
        offset = addr - BOOTV_BASE;
    } else if (addr >= BOOTP_BASE && addr < BOOTP_BASE + boot_bytes) {
        data = boot_data;
        offset = addr - BOOTP_BASE;
    } else if (addr >= FLASHV_BASE && addr < FLASHV_BASE + flash_bytes) {
        data = flash_data;
        offset = addr - FLASHV_BASE;
    } else {
        data = flash_data;
        offset = addr - FLASHP_BASE;
    }
    target_verify_block (mc, addr, blocksz/4, (unsigned*) (data + offset));
    return 1;
}

void do_program (char *filename, int cmd_location)
{
    unsigned addr;
    int progress_len, progress_step, boot_progress_len;
    void *t0;
    int ret_val;
    static int do_prog_cnt = 0;

    /* Open and detect the device. */
    atexit (quit);
    target = target_open (target_port);
    if (! target) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, _("Error detecting device -- check cable!\n"));
#endif
        exit (1);
    }
    flash_bytes = 0x200000; //target_flash_bytes (target);
    boot_bytes = target_boot_bytes (target);
    blocksz = target_block_size (target);
    devcfg_offset = target_devcfg_offset (target);
#if 0
    printf (_("    Processor: %s\n"), target_cpu_name (target));
    printf (_(" Flash memory: %d kbytes\n"), flash_bytes / 1024);
    if (boot_bytes > 0)
        printf (_("  Boot memory: %d kbytes\n"), boot_bytes / 1024);
    printf (_("         Data: %d bytes\n"), total_bytes);
#endif

    /* Verify DEVCFGx values. */
    if (boot_used) {
        if (devcfg0 == 0xffffffff) {
#if 0
#if DO_DEBUG_PRINTS
            fprintf (stderr, _("DEVCFG values are missing -- check your HEX file!\n"));
#endif
            exit (1);
#endif
        }
        if (devcfg_offset == 0xffc0) {
            /* For MZ family, clear the bit DEVSIGN0[31]. */
            boot_data[0xFFEF] &= 0x7f;
        }
    }
#if 0
    if (! verify_only) {
        /* Erase flash. */
        target_erase (target);
    }
#endif    
    ret_val = target_erase (target, cmd_location);
#if 1    
    sleep(3);
#endif    

    target_use_executive (target);

    /* Compute dirty bits for every block. */
    if (flash_used) {
        for (addr=0; addr<flash_bytes; addr+=blocksz) {
            flash_dirty [addr / blocksz] = is_flash_block_dirty (addr);
        }
    }
    if (boot_used) {
        for (addr=0; addr<boot_bytes; addr+=blocksz) {
            boot_dirty [addr / blocksz] = is_boot_block_dirty (addr);
        }
    }

    /* Compute length of progress indicator for flash memory. */
    for (progress_step=1; ; progress_step<<=1) {
        progress_len = 0;
        for (addr=0; addr<flash_bytes; addr+=blocksz) {
            if (flash_dirty [addr / blocksz])
                progress_len++;
        }
        if (progress_len / progress_step < 64) {
            progress_len /= progress_step;
            if (progress_len < 1)
                progress_len = 1;
            break;
        }
    }

    /* Compute length of progress indicator for boot memory. */
    boot_progress_len = 1;
    for (addr=0; addr<boot_bytes; addr+=blocksz) {
        if (boot_dirty [addr / blocksz])
            boot_progress_len++;
    }

    progress_count = 0;
    t0 = fix_time ();

        if (flash_used) {
#if 0
            printf (_("Program flash: "));
            print_symbols ('.', progress_len);
            print_symbols ('\b', progress_len);
#endif
            fflush (stdout);
            for (addr=0; addr<flash_bytes; addr+=blocksz) {
                if (flash_dirty [addr / blocksz]) 
                {
                    program_block (target, addr + FLASHV_BASE, cmd_location);
                    progress (progress_step);
                    //fprintf(stderr, "program_block progress : %d\n", do_prog_cnt);
                    do_prog_cnt++;
                }
            }
#if 0
            printf (_("# done\n"));
#endif
        }

        sleep(10);
        target_copy_checksum_to_sqiflash(target, cmd_location);
	sleep(60); //180
	target_erase_progmem (target);
	sleep(6); //60
	target_copy_from_sqi_to_progmem (target, cmd_location);
	sleep(45); //150
        printf("\nDone.");
}

void do_read (char *filename, unsigned base, unsigned nbytes)
{
    FILE *fd;
    unsigned len, addr, data [256], progress_step;
    void *t0;

    fd = fopen (filename, "wb");
    if (! fd) {
        perror (filename);
        exit (1);
    }
    printf (_("       Memory: total %d bytes\n"), nbytes);

    /* Use 1kbyte blocks. */
    blocksz = 1024;

    /* Open and detect the device. */
    atexit (quit);
    target = target_open (target_port);
    if (! target) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, _("Error detecting device -- check cable!\n"));
#endif
        exit (1);
    }
    target_use_executive (target);
    for (progress_step=1; ; progress_step<<=1) {
        len = 1 + nbytes / progress_step / blocksz;
        if (len < 64)
            break;
    }
    printf ("         Read: " );
    print_symbols ('.', len);
    print_symbols ('\b', len);
    fflush (stdout);

    progress_count = 0;
    t0 = fix_time ();
    for (addr=base; addr-base<nbytes; addr+=blocksz) {
        progress (progress_step);
        target_read_block (target, addr, blocksz/4, data);
        if (fwrite (data, 1, blocksz, fd) != blocksz) {
#if DO_DEBUG_PRINTS
            fprintf (stderr, "%s: write error!\n", filename);
#endif
            exit (1);
        }
    }
    printf (_("# done\n"));
    printf (_("         Rate: %ld bytes per second\n"),
        nbytes * 1000L / mseconds_elapsed (t0));
    fclose (fd);
}

/*
 * Print copying part of license
 */
static void gpl_show_copying (void)
{
    printf ("%s.\n\n", copyright);
    printf ("This program is free software; you can redistribute it and/or modify\n");
    printf ("it under the terms of the GNU General Public License as published by\n");
    printf ("the Free Software Foundation; either version 2 of the License, or\n");
    printf ("(at your option) any later version.\n");
    printf ("\n");
    printf ("This program is distributed in the hope that it will be useful,\n");
    printf ("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    printf ("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    printf ("GNU General Public License for more details.\n");
    printf ("\n");
}


void do_sqi_to_progmem_copy_and_run(int cmd_location)
{
    unsigned addr;
    int progress_len, progress_step, boot_progress_len;
    void *t0;
    int ret_val;
    static int do_prog_cnt = 0;

    /* Open and detect the device. */
    atexit (quit);
    target = target_open (target_port);
    if (! target) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, _("Error detecting device -- check cable!\n"));
#endif
        exit (1);
    }
    target_erase_progmem (target);
    sleep(6); //60
    target_copy_from_sqi_to_progmem (target, cmd_location);
    sleep(45); //150
    printf("Done.");
}

/*
 * Print NO WARRANTY part of license
 */
static void gpl_show_warranty (void)
{
    printf ("%s.\n\n", copyright);
    printf ("BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY\n");
    printf ("FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN\n");
    printf ("OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES\n");
    printf ("PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED\n");
    printf ("OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n");
    printf ("MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS\n");
    printf ("TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE\n");
    printf ("PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,\n");
    printf ("REPAIR OR CORRECTION.\n");
    printf("\n");
    printf ("IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING\n");
    printf ("WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR\n");
    printf ("REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,\n");
    printf ("INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING\n");
    printf ("OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED\n");
    printf ("TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY\n");
    printf ("YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER\n");
    printf ("PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE\n");
    printf ("POSSIBILITY OF SUCH DAMAGES.\n");
    printf("\n");
}

int main (int argc, char **argv)
{
    int ch, read_mode = 0;
    unsigned base, nbytes;
    int cmd_location;
    static const struct option long_options[] = {
        { "help",        0, 0, 'h' },
        { "warranty",    0, 0, 'W' },
        { "copying",     0, 0, 'C' },
        { "version",     0, 0, 'V' },
        { "skip-verify", 0, 0, 'S' },
        { NULL,          0, 0, 0 },
    };


#if 0
    fp = fopen("log_bin_data_1.bin", "w");
#endif

    /* Set locale and message catalogs. */
    setlocale (LC_ALL, "");
#if defined (__CYGWIN32__) || defined (MINGW32)
    /* Files with localized messages should be placed in
     * the current directory or in c:/Program Files/pic32prog. */
    if (access ("./ru/LC_MESSAGES/pic32prog.mo", R_OK) == 0)
        bindtextdomain ("pic32prog", ".");
    else
        bindtextdomain ("pic32prog", "c:/Program Files/pic32prog");
#else
    bindtextdomain ("pic32prog", "/usr/local/share/locale");
#endif
    textdomain ("pic32prog");

    setvbuf (stdout, (char *)NULL, _IOLBF, 0);
    setvbuf (stderr, (char *)NULL, _IOLBF, 0);
    //printf (_("Programmer for Microchip PIC32 microcontrollers, Version %s\n"), VERSION);
    progname = argv[0];
    //copyright = _("    Copyright: (C) 2011-2015 Serge Vakulenko");
    signal (SIGINT, interrupted);
#ifdef __linux__
    signal (SIGHUP, interrupted);
#endif
    signal (SIGTERM, interrupted);

    while ((ch = getopt_long (argc, argv, "vDRhrpCVWSd:",
      long_options, 0)) != -1) {
        switch (ch) {
#if 0
        case 'v':
            ++verify_only;
            continue;
#endif
        case 'D':
            ++debug_level;
            continue;
        case 'R':
            cmd_location = 1;
            do_sqi_to_progmem_copy_and_run(cmd_location);
            return 0;
#if 0
        case 'r':
            ++read_mode;
            continue;
        case 'p':
            ++power_on;
            continue;
        case 'd':
            target_port = optarg;
            continue;
        case 'h':
            break;
        case 'V':
            /* Version already printed above. */
            return 0;
        case 'C':
            gpl_show_copying ();
            return 0;
        case 'W':
            gpl_show_warranty ();
            return 0;
        case 'S':
            ++skip_verify;
            continue;
#endif
        }
usage:
#if 0
        printf ("%s.\n\n", copyright);
        printf ("PIC32prog comes with ABSOLUTELY NO WARRANTY; for details\n");
        printf ("use `--warranty' option. This is Open Source software. You are\n");
        printf ("welcome to redistribute it under certain conditions. Use the\n");
        printf ("'--copying' option for details.\n\n");
        printf ("Probe:\n");
        printf ("       pic32prog\n");
        printf ("\nWrite flash memory:\n");
        printf ("       pic32prog [-v] file.srec\n");
        printf ("       pic32prog [-v] file.hex\n");
        printf ("\nRead memory:\n");
        printf ("       pic32prog -r file.bin address length\n");
        printf ("\nArgs:\n");
        printf ("       file.srec           Code file in SREC format\n");
        printf ("       file.hex            Code file in Intel HEX format\n");
        printf ("       file.bin            Code file in binary format\n");
        printf ("       -v                  Verify only\n");
        printf ("       -r                  Read mode\n");
        printf ("       -d device           Use serial device\n");
        printf ("       -p                  Leave board powered on\n");
        printf ("       -D                  Debug mode\n");
        printf ("       -h, --help          Print this help message\n");
        printf ("       -V, --version       Print version\n");
        printf ("       -C, --copying       Print copying information\n");
        printf ("       -W, --warranty      Print warranty information\n");
        printf ("       -S, --skip-verify   Skip the write verification step\n");
        printf ("\n");
#endif
        return 0;
    }
    //printf ("%s\n", copyright);
    argc -= optind;
    argv += optind;

    memset (boot_data, ~0, BOOT_BYTES);
    memset (flash_data, ~0, FLASH_BYTES);

    switch (argc) {
    case 0:
        do_probe ();
        break;
    case 1:
        if ( ! read_bin (argv[0])) {
#if DO_DEBUG_PRINTS
            fprintf (stderr, _("%s: bad file format\n"), argv[0]);
#endif
            exit (1);
        }
        cmd_location = 1;
        do_program (argv[0], cmd_location);
        break;
    case 2:
        if ( ! read_bin (argv[0])) {
#if DO_DEBUG_PRINTS
            fprintf (stderr, _("%s: bad file format\n"), argv[0]);
#endif
            exit (1);
        }
        cmd_location = strtoul(argv[1], NULL, 0);
        //printf("main(): cmd_location: %d\n", cmd_location);
        do_program (argv[0], cmd_location);
        break;
    case 3:
        if (! read_mode)
            goto usage;
        base = strtoul (argv[1], 0, 0);
        nbytes = strtoul (argv[2], 0, 0);
        do_read (argv[0], base, nbytes);
        break;
    default:
        goto usage;
    }
    quit ();
#if 0
    fclose(fp);
#endif
    return 0;
}
