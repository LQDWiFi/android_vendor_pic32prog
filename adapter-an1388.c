/*
 * Interface to PIC32 Microchip AN1388 USB bootloader (new).
 *
 * Copyright (C) 2011-2013 Serge Vakulenko
 *
 * This file is part of PIC32PROG project, which is distributed
 * under the terms of the GNU General Public License (GPL).
 * See the accompanying file "COPYING" for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "adapter.h"
#include "hidapi.h"
#include "pic32.h"

#define FRAME_SOH           0x01
#define FRAME_EOT           0x04
#define FRAME_DLE           0x10

#define CMD_READ_VERSION      0x01
#define CMD_ERASE_SQIFLASH_1     0x02
#define CMD_ERASE_SQIFLASH_2     0x03
#define CMD_PROGRAM_FLASH_1   0x04
#define CMD_PROGRAM_FLASH_2   0x05
#define CMD_READ_CRC          0x06
#define CMD_JUMP_APP          0x07
#define CMD_ERASE_NVMFLASH    0x08
#define CMD_COPY_SQIFLASH_1_TO_PROGMEM        0x09
#define CMD_COPY_SQIFLASH_2_TO_PROGMEM        0x0a
#define CMD_COPY_CHKSUM_TO_SQIFLASH_1         0x0b
#define CMD_COPY_CHKSUM_TO_SQIFLASH_2         0x0c

extern unsigned short gFlashChecksum;

typedef struct {
    /* Common part */
    adapter_t adapter;

    /* Device handle for libusb. */
    hid_device *hiddev;

    unsigned char reply [64];
    int reply_len;

} an1388_adapter_t;

/*
 * Identifiers of USB adapter.
 */
#define MICROCHIP_VID           0x04d8
#define BOOTLOADER_PID          0x003c  /* Microchip AN1388 Bootloader */

/*
 * Calculate checksum.
 */
static unsigned calculate_crc (unsigned crc, unsigned char *data, unsigned nbytes)
{
    static const unsigned short crc_table [16] = {
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    };
    unsigned i;

    while (nbytes--) {
        i = (crc >> 12) ^ (*data >> 4);
        crc = crc_table[i & 0x0F] ^ (crc << 4);
        i = (crc >> 12) ^ (*data >> 0);
        crc = crc_table[i & 0x0F] ^ (crc << 4);
        data++;
    }
    return crc & 0xffff;
}

static void an1388_send (hid_device *hiddev, unsigned char *buf, unsigned nbytes)
{
    if (debug_level > 0) {
        int k;
#if DO_DEBUG_PRINTS
        fprintf (stderr, "---Send");
#endif
        for (k=0; k<nbytes; ++k) {
            if (k != 0 && (k & 15) == 0)
            {
#if DO_DEBUG_PRINTS
                fprintf (stderr, "\n       ");
#endif
            }
#if DO_DEBUG_PRINTS
            fprintf (stderr, " %02x", buf[k]);
#endif
        }
#if DO_DEBUG_PRINTS
        fprintf (stderr, "\n");
#endif
    }
    //hid_write (hiddev, buf, 64);
    hid_write (hiddev, buf, 128);
}

static int an1388_recv (hid_device *hiddev, unsigned char *buf)
{
    int n;
    static int cnt = 0;

#if DO_DEBUG_PRINTS_IMP
    fprintf(stderr, "Inside an1388_recv cnt : %d\n", cnt);
#endif
    usleep(1000);

    if (cnt == 6558)
    {
        cnt = 6558; //For breakpoint
        //fprintf(stderr, "Before Exiting : %d\n", cnt);
    }
    cnt++;

    n = hid_read (hiddev, buf, 64);
    if (n <= 0) {
#if DO_DEBUG_PRINTS
        //fprintf (stderr, "hidboot: error %d receiving packet\n", n);
#endif
        //exit (-1);
    }
    if (debug_level > 0) 
    {
        int k;
#if DO_DEBUG_PRINTS
        fprintf (stderr, "---Recv");
#endif
        for (k=0; k<n; ++k) {
            if (k != 0 && (k & 15) == 0)
            {
#if DO_DEBUG_PRINTS
                fprintf (stderr, "\n       ");
#endif
            }
#if DO_DEBUG_PRINTS
            fprintf (stderr, " %02x", buf[k]);
#endif
        }
#if DO_DEBUG_PRINTS
        fprintf (stderr, "\n");
#endif
    }
    return n;
}

static inline unsigned add_byte (unsigned char c,
    unsigned char *buf, unsigned indx)
{
    if (c == FRAME_EOT || c == FRAME_SOH || c == FRAME_DLE)
        buf[indx++] = FRAME_DLE;
    buf[indx++] = c;
    return indx;
}

/*
 * Send a request to the device.
 * Store the reply into the a->reply[] array.
 */
static void an1388_command (an1388_adapter_t *a, unsigned char cmd,
    unsigned char *data, unsigned data_len)
{
    //unsigned char buf [64];
    unsigned char buf [128];
    unsigned i, n, c, crc;

    if (debug_level > 0) 
    {
        int k;
#if DO_DEBUG_PRINTS
        fprintf (stderr, "---Cmd%d", cmd);
#endif
        for (k=0; k<data_len; ++k) {
            if (k != 0 && (k & 15) == 0)
            {
#if DO_DEBUG_PRINTS
                fprintf (stderr, "\n       ");
#endif
            }
#if DO_DEBUG_PRINTS
            fprintf (stderr, " %02x", data[k]);
#endif
        }
#if DO_DEBUG_PRINTS
        fprintf (stderr, "\n");
#endif
    }
    memset (buf, FRAME_EOT, sizeof(buf));
    n = 0;
    buf[n++] = FRAME_SOH;

    n = add_byte (cmd, buf, n);
    crc = calculate_crc (0, &cmd, 1);

    if (data_len > 0) {
        for (i=0; i<data_len; ++i)
            n = add_byte (data[i], buf, n);
        crc = calculate_crc (crc, data, data_len);
    }
    n = add_byte (crc, buf, n);
    n = add_byte (crc >> 8, buf, n);

    buf[n++] = FRAME_EOT;
#if 0
    if ((cmd == CMD_PROGRAM_FLASH) && (data[1] == 0xF5) && (data[2] == 0x80))
    {
       extern FILE *fp;
       int cntr2 = 0;
       for(cntr2=0; cntr2<n; cntr2++)
       {
           fprintf(fp, "0x%X ", buf[cntr2]);
       }
       fprintf(fp, "\n");
    }
#endif

    an1388_send (a->hiddev, buf, n);

    if (cmd == CMD_JUMP_APP) {
        /* No reply expected. */
        return;
    }
    n = an1388_recv (a->hiddev, buf);
#if 0
    c = 0;
    for (i=0; i<n; ++i) {
        switch (buf[i]) {
        default:
            a->reply[c++] = buf[i];
            continue;
        case FRAME_DLE:
            a->reply[c++] = buf[++i];
            continue;
        case FRAME_SOH:
            c = 0;
            continue;
        case FRAME_EOT:
            a->reply_len = 0;
            if (c > 2) {
                unsigned crc = a->reply[c-2] | (a->reply[c-1] << 8);
                if (crc == calculate_crc (0, a->reply, c-2))
                    a->reply_len = c - 2;
            }
            if (a->reply_len > 0 && debug_level > 0) {
                int k;
#if DO_DEBUG_PRINTS
                fprintf (stderr, "--->>>>");
#endif
                for (k=0; k<a->reply_len; ++k) {
                    if (k != 0 && (k & 15) == 0)
                    {
#if DO_DEBUG_PRINTS
                        fprintf (stderr, "\n       ");
#endif
                    }
#if DO_DEBUG_PRINTS
                    fprintf (stderr, " %02x", a->reply[k]);
#endif
                }
#if DO_DEBUG_PRINTS
                fprintf (stderr, "\n");
#endif
            }
            return;
        }
    }
#endif
}

static void an1388_close (adapter_t *adapter, int power_on)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;

    /* Jump to application. */
    an1388_command (a, CMD_JUMP_APP, 0, 0);
    free (a);
}

/*
 * Return the Device Identification code
 */
static unsigned an1388_get_idcode (adapter_t *adapter)
{
    return 0xDEAFB00B;
}

/*
 * Read a configuration word from memory.
 */
static unsigned an1388_read_word (adapter_t *adapter, unsigned addr)
{
    /* Not supported by booloader. */
    return 0;
}

/*
 * Write a configuration word to flash memory.
 */
static void an1388_program_word (adapter_t *adapter,
    unsigned addr, unsigned word)
{
    /* Not supported by booloader. */
    if (debug_level > 0)
    {
#if DO_DEBUG_PRINTS
        fprintf (stderr, "hidboot: program word at %08x: %08x\n", addr, word);
#endif
    }
}

/*
 * Verify a block of memory.
 */
static void an1388_verify_data (adapter_t *adapter,
    unsigned addr, unsigned nwords, unsigned *data)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;
    unsigned char request [8];
    unsigned data_crc, flash_crc, nbytes = nwords * 4;

#if DO_DEBUG_PRINTS
    fprintf (stderr, "hidboot: verify %d bytes at %08x\n", nbytes, addr);
#endif
    request[0] = addr;
    request[1] = addr >> 8;
    request[2] = addr >> 16;
    request[3] = (addr >> 24) + 0x80;
    request[4] = nbytes;
    request[5] = nbytes >> 8;
    request[6] = nbytes >> 16;
    request[7] = nbytes >> 24;
    an1388_command (a, CMD_READ_CRC, request, 8);
    if (a->reply_len != 3 || a->reply[0] != CMD_READ_CRC) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, "hidboot: cannot read crc at %08x\n", addr);
#endif
        //exit (-1);
    }
    flash_crc = a->reply[1] | a->reply[2] << 8;

    data_crc = calculate_crc (0, (unsigned char*) data, nbytes);
    if (flash_crc != data_crc) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, "hidboot: checksum failed at %08x: sum=%04x, expected=%04x\n",
            addr, flash_crc, data_crc);
#endif
        //exit (-1);
    }
}

static void set_flash_address (an1388_adapter_t *a, unsigned addr, int cmd_location)
{
    unsigned char request[7];
    unsigned sum, i;

    request[0] = 2;
    request[1] = 0;
    request[2] = 0;
    request[3] = 4;             /* Type: linear address record */
    request[4] = addr >> 24;
    request[5] = addr >> 16;

    /* Compute checksum. */
    sum = 0;
    for (i=0; i<6; i++)
        sum += request[i];
    request[6] = -sum;

    if (cmd_location == 1)
    {
        an1388_command (a, CMD_PROGRAM_FLASH_1, request, 7);
        if (a->reply_len != 1 || a->reply[0] != CMD_PROGRAM_FLASH_1) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: error setting flash address at %08x\n", addr);
#endif
            //exit (-1);
        }  
    } else if (cmd_location == 2)
    {
        an1388_command (a, CMD_PROGRAM_FLASH_2, request, 7);
        if (a->reply_len != 1 || a->reply[0] != CMD_PROGRAM_FLASH_2) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: error setting flash address at %08x\n", addr);
#endif
            //exit (-1);
        }  
    }
}

static void program_flash (an1388_adapter_t *a,
    unsigned addr, unsigned char *data, unsigned nbytes, int cmd_location)
{
    unsigned char request[64];
    unsigned sum, empty, i;

    /* Skip empty blocks. */
    empty = 1;
    for (i=0; i<nbytes; i++) {
        if (data[i] != 0xff) {
            empty = 0;
            break;
        }
    }
    if (empty)
    {
        return;
    }
#if 0    
        {
        int j, nptrs;
        #define SIZE 100
        void *pbuffer[100];
        char **strings;
        nptrs = backtrace(pbuffer, SIZE);
        strings = backtrace_symbols(pbuffer, nptrs);
        if (strings == NULL)
        {
        } else
        {
            for(j=0; j<nptrs; j++)
            {
                printf("Backtrace: %s\n", strings[j]);
            }
            free (strings);
        }


    }
#endif

#if DO_DEBUG_PRINTS
    //fprintf (stderr, "hidboot: program %d bytes at %08x: %02x-%02x-...-%02x\n",
    //    nbytes, addr, data[0], data[1], data[31]);
    usleep(3000);
#endif

    request[0] = nbytes;
    request[1] = addr >> 8;
    request[2] = addr;
    request[3] = 0;             /* Type: data record */
#if DO_DEBUG_PRINTS
    //fprintf(stderr, "nbytes: %d\n", nbytes);
    usleep(1000);
#endif


    memcpy (request+4, data, nbytes);
#if DO_DEBUG_PRINTS
    //fprintf(stderr, "After memcpy\n");
    usleep(1000);
#endif

    /* Compute checksum. */
    sum = 0;
    empty = 1;
    for (i=0; i<nbytes+4; i++) {
        sum += request[i];
    }
#if DO_DEBUG_PRINTS
    //fprintf(stderr, "After summation\n");
    usleep(1000);
#endif
    request[nbytes+4] = -sum;

#if DO_DEBUG_PRINTS
    //fprintf(stderr, "Just before calling CMD_PROGRAM_FLASH\n");
    usleep(1000);
#endif

#if 0
    {
        extern FILE *fp;
        int ctr1;
        fprintf(fp, "0x%x: ", addr);
        for (ctr1=0; ctr1<(nbytes+5); ctr1++)
        {
            fprintf(fp, "0x%X ", request[ctr1]);
        }
        fprintf(fp, "\n");
        
    }   
#endif
    if (cmd_location == 1)
    {
        an1388_command (a, CMD_PROGRAM_FLASH_1, request, nbytes + 5);
        if (a->reply_len != 1 || a->reply[0] != CMD_PROGRAM_FLASH_1) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: error programming flash at %08x\n", addr);
#endif
            //exit (-1);
        }  
    } else if (cmd_location == 2)
    {
        an1388_command (a, CMD_PROGRAM_FLASH_2, request, nbytes + 5);
        if (a->reply_len != 1 || a->reply[0] != CMD_PROGRAM_FLASH_2) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: error programming flash at %08x\n", addr);
#endif
            //exit (-1);
        }  
    }
}

/*
 * Flash write, 1-kbyte blocks.
 */
static void an1388_program_block (adapter_t *adapter,
    unsigned addr, unsigned *data, int cmd_location)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;
    unsigned i;

    set_flash_address (a, addr, cmd_location);
    for (i=0; i<256; i+=8) {
        /* 8 words per cycle. */
#if DO_DEBUG_PRINTS
        //fprintf(stderr, "Calling program flash from an1388_program_block\n");
#endif
        usleep(1000);
        program_flash (a, addr, (unsigned char*) data, 32, cmd_location);
        data += 8;
        addr += 32;
    }
}

/*
 * Erase all flash memory.
 */
static void an1388_erase_chip (adapter_t *adapter, int cmd_location)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;

#if DO_DEBUG_PRINTS
    //fprintf (stderr, "hidboot: erase chip\n");
#endif
    if (cmd_location == 1)
    {
        an1388_command (a, CMD_ERASE_SQIFLASH_1, 0, 0);
        if (a->reply_len != 1 || a->reply[0] != CMD_ERASE_SQIFLASH_1) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: Erase failed\n");
#endif
            //exit (-1);
        }
    } else if (cmd_location == 2)
    {
        an1388_command (a, CMD_ERASE_SQIFLASH_2, 0, 0);
        if (a->reply_len != 1 || a->reply[0] != CMD_ERASE_SQIFLASH_2) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: Erase failed\n");
#endif
            //exit (-1);
        }
    }
}

/*
 * Erase all nvm flash program memory.
 */
static void an1388_erase_progmem (adapter_t *adapter)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;

#if DO_DEBUG_PRINTS
    //fprintf (stderr, "hidboot: erase program memory\n");
#endif
    an1388_command (a, CMD_ERASE_NVMFLASH, 0, 0);
    if (a->reply_len != 1 || a->reply[0] != CMD_ERASE_NVMFLASH) {
#if DO_DEBUG_PRINTS
        //fprintf (stderr, "hidboot: Erase failed\n");
#endif
        //exit (-1);
    }
}

/*
 * Erase all flash memory.
 */
static void an1388_copy_from_sqi_to_progmem (adapter_t *adapter, int cmd_location)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;

#if DO_DEBUG_PRINTS
    //fprintf (stderr, "hidboot: copy SQI flash to Program Memory\n");
#endif
    if (cmd_location == 1)
    {
        an1388_command (a, CMD_COPY_SQIFLASH_1_TO_PROGMEM, 0, 0);
        if (a->reply_len != 1 || a->reply[0] != CMD_COPY_SQIFLASH_1_TO_PROGMEM) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: copy SQI flash to Program Memory failed\n");
#endif
            //exit (-1);
        }  
    } else if (cmd_location == 2)
    {
        an1388_command (a, CMD_COPY_SQIFLASH_2_TO_PROGMEM, 0, 0);
        if (a->reply_len != 1 || a->reply[0] != CMD_COPY_SQIFLASH_2_TO_PROGMEM) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: copy SQI flash to Program Memory failed\n");
#endif
            //exit (-1);
        }  
    }
}

static void an1388_copy_checksum_to_sqiflash (adapter_t *adapter, int cmd_location)
{
    an1388_adapter_t *a = (an1388_adapter_t*) adapter;
    unsigned char request[2];

    request[0] = (gFlashChecksum & 0xFF00) >> 8;
    request[1] = (gFlashChecksum & 0x00FF);

#if DO_DEBUG_PRINTS
    //fprintf (stderr, "hidboot: copy SQI flash to Program Memory\n");
#endif
    if (cmd_location == 1)
    {
        an1388_command (a, CMD_COPY_CHKSUM_TO_SQIFLASH_1, request, 2);
        if (a->reply_len != 1 || a->reply[0] != CMD_COPY_CHKSUM_TO_SQIFLASH_1) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: copy SQI flash to Program Memory failed\n");
#endif
            //exit (-1);
        }  
    } else if (cmd_location == 2)
    {
        an1388_command (a, CMD_COPY_CHKSUM_TO_SQIFLASH_2, request, 2);
        if (a->reply_len != 1 || a->reply[0] != CMD_COPY_CHKSUM_TO_SQIFLASH_2) {
#if DO_DEBUG_PRINTS
            //fprintf (stderr, "hidboot: copy SQI flash to Program Memory failed\n");
#endif
            //exit (-1);
        }  
    }
}

/*
 * Initialize adapter hidboot.
 * Return a pointer to a data structure, allocated dynamically.
 * When adapter not found, return 0.
 */
adapter_t *adapter_open_an1388 (void)
{
    an1388_adapter_t *a;
    hid_device *hiddev;

    hiddev = hid_open (MICROCHIP_VID, BOOTLOADER_PID, 0);
    if (! hiddev) {
#if DO_DEBUG_PRINTS
        /*fprintf (stderr, "AN1388 bootloader not found: vid=%04x, pid=%04x\n",
            MICROCHIP_VID, BOOTLOADER_PID);*/
#endif
        return 0;
    }
    a = calloc (1, sizeof (*a));
    if (! a) {
#if DO_DEBUG_PRINTS
        fprintf (stderr, "Out of memory\n");
#endif
        return 0;
    }

    // Set the hid_read() function to be non-blocking.
    hid_set_nonblocking(hiddev, 1);

    a->hiddev = hiddev;

    
    /* Read version of adapter. */
    an1388_command (a, CMD_READ_VERSION, 0, 0);
#if 0
    printf ("      Adapter: AN1388 Bootloader Version %d.%d\n",
        a->reply[1], a->reply[2]);
#endif

    a->adapter.user_start = 0x1d000000;
    a->adapter.user_nbytes = 512 * 1024;
#if 0
    printf (" Program area: %08x-%08x\n", a->adapter.user_start,
        a->adapter.user_start + a->adapter.user_nbytes - 1);
#endif

    /* User functions. */
    a->adapter.close = an1388_close;
    a->adapter.get_idcode = an1388_get_idcode;
    a->adapter.read_word = an1388_read_word;
    a->adapter.verify_data = an1388_verify_data;
    a->adapter.erase_chip = an1388_erase_chip;
    a->adapter.program_block = an1388_program_block;
    a->adapter.program_word = an1388_program_word;
    a->adapter.erase_progmem = an1388_erase_progmem;
    a->adapter.copy_from_sqi_to_progmem = an1388_copy_from_sqi_to_progmem;
    a->adapter.copy_checksum_to_sqiflash = an1388_copy_checksum_to_sqiflash;

    return &a->adapter;
}

