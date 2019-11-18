/*  2019-08-12 @tt, create for urgent message.
 *
 *  This file is now only valid for the rtk-based project,
 *  provide one interface to send urgent command to the vehicle in one of the mulitiply communication channels,
 *  when the others channels are not available.
 *
 */

#include "rtklib.h"

/* private global defination of the protocol. */
#ifndef STATIC_URGENT_MSG_FLAG
#define STATIC_URGENT_MSG_FLAG
/* define the urgent command version. */
#define URGENT_CMD_VERSION_MAGIC            (0x5A)
#define URGENT_CMD_VERSION_MAJOR            (0x31)
#define URGENT_CMD_VERSION_MINOR            (0x30)
#define URGENT_CMD_VERSION_PATCH            (0x36)
#define URGENT_VERSION                      ((URGENT_CMD_VERSION_MAGIC << 24) & 0xFF000000) | \
                                            ((URGENT_CMD_VERSION_MAJOR << 16) & 0xFF0000) | \
                                            ((URGENT_CMD_VERSION_MINOR << 8) & 0xFF00) | \
                                            (URGENT_CMD_VERSION_PATCH & 0xFF)

/* the fixed bytes number before the payload. */
/* #define UGTMSG_PREP     (4) */
#define UGTMSG_PREP     (12)
/* the fixed bytes number after the payload, here is the crc32. */
#define UGTMSG_AFTP     (4)
/* the urgent header low byte. */
#define UGTHL           (0xFE)
/* the urgent header high byte. */
#define UGTHH           (0xDC)

#define UGTH0           (0xFE)
#define UGTH1           (0xEF)
#define UGTH2           (0xDC)
#define UGTH3           (0xCD)
#define UGTH4           (0xBA)
#define UGTH5           (0xAB)
#define UGTH6           (0x98)
#define UGTH7           (0x89)
#define UGTH8           (0x76)
#define UGTH9           (0x67)
#endif

/* private dd message defination. */


/* urgent private message handler. */
typedef struct _ugt_priv_s_ {
    urgent_t * pugt;
    stream_t * pstm;
    unsigned int state;
} ugt_priv_t;

/* global static urgent message structure. */
static ugt_priv_t * ppugt = NULL;

/* initialize the crc32 table. */
static unsigned int ugt_crctable[256] = { 0 };

/* create the crc32 table. */
static void ugt_gencrc32(void)
{
    unsigned int i = 0, j = 0;
    unsigned int CRC = 0;
    for(i = 0; i < 256; i++)
    {
        CRC = i;
        for(j = 0; j < 8; j++)
        {
            if(CRC & 1)
            {
                CRC = (CRC >> 1) ^ 0xEDB88320;
            }
            else
            {
                CRC >>= 1;
            }
        }
        ugt_crctable[i] = CRC;
    }
}

/* used to calc the urgent crc. we calculate the whole frame before the crc part. */
static unsigned int ugt_msg2buf(urgent_t * ugtmsg, unsigned char * ugtbuf)
{
    if(ugtmsg && ugtbuf)
    {
        ugtbuf[0] = ugtmsg->h0;
        ugtbuf[1] = ugtmsg->h1;
        ugtbuf[2] = ugtmsg->h2;
        ugtbuf[3] = ugtmsg->h3;
        ugtbuf[4] = ugtmsg->h4;
        ugtbuf[5] = ugtmsg->h5;
        ugtbuf[6] = ugtmsg->h6;
        ugtbuf[7] = ugtmsg->h7;
        ugtbuf[8] = ugtmsg->h8;
        ugtbuf[9] = ugtmsg->h9;
        ugtbuf[10] = ugtmsg->pl;
        ugtbuf[11] = ugtmsg->ct;
        /* copy the payload part. */
        memcpy(&ugtbuf[UGTMSG_PREP], ugtmsg->bf, ugtmsg->pl);
        return (UGTMSG_PREP + ugtbuf[10]);
    }

    return 0;
}

/* used to turn structure to buffer. */
static unsigned int ugt_msg2buf1(urgent_t * ugtmsg, unsigned char * ugtbuf)
{
    if(ugtmsg && ugtbuf)
    {
        ugtbuf[0] = ugtmsg->h0;
        ugtbuf[1] = ugtmsg->h1;
        ugtbuf[2] = ugtmsg->h2;
        ugtbuf[3] = ugtmsg->h3;
        ugtbuf[4] = ugtmsg->h4;
        ugtbuf[5] = ugtmsg->h5;
        ugtbuf[6] = ugtmsg->h6;
        ugtbuf[7] = ugtmsg->h7;
        ugtbuf[8] = ugtmsg->h8;
        ugtbuf[9] = ugtmsg->h9;
        ugtbuf[10] = ugtmsg->pl;
        ugtbuf[11] = ugtmsg->ct;
        memcpy(&ugtbuf[UGTMSG_PREP], ugtmsg->bf, ugtmsg->pl);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 0] = (unsigned char)ugtmsg->cc;
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 1] = (unsigned char)((ugtmsg->cc) >> 8);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 2] = (unsigned char)((ugtmsg->cc) >> 16);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 3] = (unsigned char)((ugtmsg->cc) >> 24);
        return (UGTMSG_PREP + ugtbuf[10] + UGTMSG_AFTP);
    }

    return 0;
}
/*  calculate the crc32.
 *
 *  @ugtmsg:    the whole urgent message frame;
 *  @pcrc:      pointer to store the calculated crc value.
 *  @return:    0 for crc calculate done, others for failed.
 */
static int ugt_calcrc32(urgent_t * ugtmsg, unsigned int * pcrc)
{
    unsigned int i = 0;
    unsigned int crc = 0;
    unsigned char * ugt_tmpbuf = NULL;
    unsigned int ugt_tmplen = 0;
    if(ugtmsg)
    {
        ugt_tmplen = UGTMSG_PREP + ugtmsg->pl;
        ugt_tmpbuf = malloc(ugt_tmplen);
        if(ugt_tmpbuf)
        {
            ugt_tmplen = ugt_msg2buf(ugtmsg, ugt_tmpbuf);
            if(ugt_tmplen)
            {
                for(i = 0; i < ugt_tmplen; i++)
                {
                    crc = ugt_crctable[(crc ^ ugt_tmpbuf[i]) & 0xFF] ^ (crc >> 8);
                }
                free(ugt_tmpbuf);
                ugt_tmpbuf = NULL;
                *pcrc = crc;
                return 0;
            }
            free(ugt_tmpbuf);
            ugt_tmpbuf = NULL;
            return -3;
        }
        return -2;
    }

    return -1;
}

/* fill the urgent message by ui commands.
 *
 * @cmd_type:   the command type, only 10 command type are supported, please refer to the protocol.
 * @cmd_buf:    the payload part of the command.
 * @buf_len:    the payload len.
 * @return:     0 is fill succeed, others are failed.
 */
int ugt_fill(unsigned char cmd_type, unsigned char * cmd_buf, unsigned int buf_len)
{
    int ret = 0;
    if(ppugt && (ppugt->state == UGT_INIT || ppugt->state == UGT_DONE) && ppugt->pugt)
    {
        ppugt->pugt->h0 = UGTH0;
        ppugt->pugt->h1 = UGTH1;
        ppugt->pugt->h2 = UGTH2;
        ppugt->pugt->h3 = UGTH3;
        ppugt->pugt->h4 = UGTH4;
        ppugt->pugt->h5 = UGTH5;
        ppugt->pugt->h6 = UGTH6;
        ppugt->pugt->h7 = UGTH7;
        ppugt->pugt->h8 = UGTH8;
        ppugt->pugt->h9 = UGTH9;
        ppugt->pugt->pl = (unsigned char)buf_len;
        ppugt->pugt->ct = cmd_type;
        ppugt->pugt->bf = malloc(ppugt->pugt->pl);
        if(!ppugt->pugt->bf) return -2;
        memcpy(ppugt->pugt->bf, cmd_buf, buf_len);
        ret = ugt_calcrc32(ppugt->pugt, &ppugt->pugt->cc);
        if(!ret)
        {
            ppugt->state = UGT_FILL;
        }
        return ret;
    }

    return -1;
}

/* get current urgent state. */
unsigned int ugt_getstate(void)
{
    if(ppugt) return ppugt->state;

    return UGT_UINI;
}

/* send current filled message, this function and ugt_fill could send any command to the fc. */
int ugt_send(void)
{
    int ret = 0;
    unsigned char * tmp_sendbuf = NULL;
    unsigned int tmp_sendlen = 0;
    if(ppugt && ppugt->state == UGT_FILL)
    {
        tmp_sendbuf = malloc(UGTMSG_PREP + ppugt->pugt->pl + UGTMSG_AFTP);
        if(!tmp_sendbuf) return -2;
        tmp_sendlen = ugt_msg2buf1(ppugt->pugt, tmp_sendbuf);
        if(strwrite(ppugt->pstm, tmp_sendbuf, (int)tmp_sendlen))
        {
            ret = 0;
        }
        else
        {
            ret = -3;
        }
        if(tmp_sendbuf)
            free(tmp_sendbuf);
        tmp_sendbuf = NULL;
        if(ppugt->pugt && ppugt->pugt->bf)
        {
            free(ppugt->pugt->bf);
            ppugt->pugt->bf = NULL;
        }
        ppugt->state = UGT_DONE;
        return ret;
    }

    return -1;
}

/* initialize the urgent structure. */
int ugt_initialize(stream_t * stream)
{
    if(!ppugt)
    {
        ppugt = malloc(sizeof(ugt_priv_t));
        memset(ppugt, 0, sizeof(ugt_priv_t));

        ppugt->pugt = malloc(sizeof(urgent_t));
        memset(ppugt->pugt, 0, sizeof(urgent_t));
        ppugt->state = UGT_INIT;
        ppugt->pstm = stream;

        memset(ugt_crctable, 0, sizeof(unsigned int) * 256);
        ugt_gencrc32();

        return 0;
    }

    return -1;
}

/* deinitialize the urgent structure. */
int ugt_deinitialize(void)
{
    if(ppugt)
    {
        if(ppugt->pugt)
        {
            if(ppugt->pugt->bf)
            {
                free(ppugt->pugt->bf);
                ppugt->pugt->bf = NULL;
            }
            free(ppugt->pugt);
            ppugt->pugt = NULL;
        }
        ppugt->pstm = NULL;
        free(ppugt);
        ppugt = NULL;
        return 0;
    }

    return -1;
}

/* interface for the application to get current urgent command version. */
int ugt_getversion(unsigned int * version)
{
    if(version)
    {
        *version = (unsigned int)URGENT_VERSION;
        return 0;
    }
    return -1;
}

/* 2019-10-14 @tt, interface for application to assemble the vehicle protocol dd and d5. */
static unsigned char ugt_prot_dd_crc_calc(unsigned char * ptr, unsigned char len)
{
    unsigned char i, crc;
    crc = 0;

    while (len--)
    {
        for(i = 0x80; i !=0; i>>= 1)
        {
            if((crc & 0x80) != 0)
            {
                crc <<= 1;
                crc ^= 0x7;
            }
            else
            {
                crc <<= 1;
            }
            if((*ptr & i) != 0)
            {
                crc ^= 0x7;
            }
        }

        ptr++;
    }

    return (crc);
}

/* 2019-10-14 @tt add dd and d5 protocol assemble function. */
void ugt_prot_dd_d5_assemble_default(unsigned short addr, unsigned char rw, unsigned short reg, unsigned char * pld, unsigned int pld_len, unsigned char * result)
{
    urgent_prot_dd_d5_t * ptr = (urgent_prot_dd_d5_t *)result;
    if(!ptr) return;
    if(rw != 0 && rw != 1) return;
    ptr->head_dd = URGENT_VEHICLE_PROT_DD_HEADER;
    ptr->len = URGENT_VEHICLE_PROT_DD_LEN_VALUE;
    ptr->counter = 0x00;
    ptr->address = addr;
    ptr->head_d5 = URGENT_VEHICLE_PROT_D5_HEADER;
    ptr->crc_d5 = 0x00;
    ptr->timstmp = 0;
    ptr->ctrltype = ((rw << 15) & 0x8000) | (reg & 0xFFF);
    memcpy_s(ptr->pld_d5, 24, pld, pld_len);
    ptr->res = 0x00;
    ptr->crc_dd = ugt_prot_dd_crc_calc((unsigned char *)&ptr->len, ptr->len + 1);
}
