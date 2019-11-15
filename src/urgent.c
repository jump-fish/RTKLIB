/* 2019-08-12 @tt, create for urgent message. */

#include "rtklib.h"

#ifndef STATIC_URGENT_MSG_FLAG
#define STATIC_URGENT_MSG_FLAG
#define UGTMSG_PREP     (4)
#define UGTMSG_AFTP     (4)
#define UGTHL           (0xFE)
#define UGTHH           (0xDC)
#define UGTCMDT_0       (0x00)
#define UGTCMDT_1       (0x01)
#define UGTCMDT_MAX     (0xFF)
#endif

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

/* used to calc the urgent crc. */
static unsigned int ugt_msg2buf(urgent_t * ugtmsg, unsigned char * ugtbuf)
{
    if(ugtmsg && ugtbuf)
    {
        ugtbuf[0] = ugtmsg->hl;
        ugtbuf[1] = ugtmsg->hh;
        ugtbuf[2] = ugtmsg->pl;
        ugtbuf[3] = ugtmsg->ct;
        memcpy(&ugtbuf[UGTMSG_PREP], ugtmsg->bf, ugtmsg->pl);
        return (UGTMSG_PREP + ugtbuf[2]);
    }

    return 0;
}

/* used to turn structure to buffer. */
static unsigned int ugt_msg2buf1(urgent_t * ugtmsg, unsigned char * ugtbuf)
{
    if(ugtmsg && ugtbuf)
    {
        ugtbuf[0] = ugtmsg->hl;
        ugtbuf[1] = ugtmsg->hh;
        ugtbuf[2] = ugtmsg->pl;
        ugtbuf[3] = ugtmsg->ct;
        memcpy(&ugtbuf[UGTMSG_PREP], ugtmsg->bf, ugtmsg->pl);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 0] = (unsigned char)ugtmsg->cc;
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 1] = (unsigned char)((ugtmsg->cc) >> 8);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 2] = (unsigned char)((ugtmsg->cc) >> 16);
        ugtbuf[UGTMSG_PREP + ugtmsg->pl + 3] = (unsigned char)((ugtmsg->cc) >> 24);
        return (UGTMSG_PREP + ugtbuf[2] + UGTMSG_AFTP);
    }

    return 0;
}
/* calculate the crc32. */
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

/* fill the urgent message by ui commands. */
int ugt_fill(unsigned char cmd_type, unsigned char * cmd_buf, unsigned int buf_len)
{
    int ret = 0;
    if(ppugt && (ppugt->state == UGT_INIT || ppugt->state == UGT_DONE) && ppugt->pugt)
    {
        ppugt->pugt->hl = UGTHL;
        ppugt->pugt->hh = UGTHH;
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

/* send current filled message. */
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
