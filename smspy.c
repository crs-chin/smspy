/*
 * SMS TPDU dessector.
 * Copyright (C) <2012>  Crs Chin<crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/* 
 * this is a GSM 03.40 spec compliant dessector
 */

/* TODO: make it a TS 23.040 spec compliant */
/* TODO: 3GPP2 C.S0015-A CDMA SMS not fully supported */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <assert.h>
#include <getopt.h>
#ifdef HAS_ICONV
 #include <iconv.h>
#endif

#ifndef SMSPY_VERSION
#define SMSPY_VERSION "1.5"
#endif

#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))
#define RETURN_VAL_IF(val,exp)  do{if(exp) return val;}while(0)

#define BUILD_FAIL_IF(exp) ((void)sizeof(char[1 - 2 * (!!(exp))]))

#ifndef NDEBUG
#define DBG_PRINT(fmt,args...)                  \
    printf(fmt,##args)
#else
#define DBG_PRINT(fmt,args...)                  \
    do{}while(0)
#endif

#define __PRINT(cfg,fmt,args...)                \
    do{                                         \
        if((cfg)->out)                          \
            fprintf((cfg)->out, fmt, ##args);   \
    }while(0)

#define PRINT(fmt,args...)                      \
    __PRINT((cfg),fmt,##args)

#define __DES_PRINT(desc,cfg,fmt,args...)           \
    do{                                             \
        if((cfg)->out && (cfg)->tp_cfg[desc->id])   \
            fprintf((cfg)->out, fmt, ##args);       \
    }while(0)

#define DES_PRINT(fmt,args...)                  \
    __DES_PRINT(desc,(cfg),fmt,##args)

#define __DES_IEI_PRINT(cfg,fmt,args...)            \
    do{                                             \
        if((cfg)->out && (cfg)->tp_cfg[TP_UD_HD])   \
            fprintf((cfg)->out, fmt, ##args);       \
    }while(0)

#define DES_IEI_PRINT(fmt,args...)              \
    __DES_IEI_PRINT((cfg),fmt,##args)

#define HEX_DUMP(pdu,len)                      \
    hex_dump(pdu,len,cfg->tp_cfg[desc->id])


#define MTI_DELIVER     1
#define MTI_DELIVER_REPORT_ERR  (1<<1)
#define MTI_DELIVER_REPORT_ACK  (1<<2)
#define MTI_STATUS_REPORT       (1<<3)
#define MTI_COMMAND     (1<<4)
#define MTI_SUBMIT      (1<<5)
#define MTI_SUBMIT_REPORT_ERR   (1<<6)
#define MTI_SUBMIT_REPORT_ACK   (1<<7)

/* CDMA */
#define MTI_CDMA_PP     (1<<8)
#define MTI_CDMA_BC     (1<<9)
#define MTI_CDMA_AK     (1<<10)

#define MTI_CDMA_DELIVER        (1<<11)
#define MTI_CDMA_SUBMIT         (1<<12)
#define MTI_CDMA_CANCEL         (1<<13)
#define MTI_CDMA_DELIVER_ACK    (1<<14)
#define MTI_CDMA_USER_ACK       (1<<15)
#define MTI_CDMA_READ_ACK       (1<<16)

#define MTI_CDMA                                \
    (MTI_CDMA_DELIVER                           \
     | MTI_CDMA_SUBMIT                          \
     | MTI_CDMA_CANCEL                          \
     | MTI_CDMA_DELIVER_ACK                     \
     | MTI_CDMA_USER_ACK                        \
     | MTI_CDMA_READ_ACK)

#define MTI_ALL ((1<<17) - 1)

#define MTI_RESERVED    (1<<8)

typedef struct _sms sms;
typedef struct _des_ctx des_ctx;
typedef struct _tpdu_parm tpdu_parm;

static int des_vpf(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_mr(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_pid(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_dcs(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_scts(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_vp(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_oa(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_da(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_dt(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_ra(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_st(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_udl(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_mn(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_ct(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_cdl(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_cd(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_fcs(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_udhi(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_ud(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
static int des_pi(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);

static int des_smsc(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);

static int des_iei_reserved(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_not_used(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_concat(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_special(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_port_8bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_port_16bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_smsc_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_udh_src_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_concat_16bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_wireless_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_text_format(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_predefined_sound(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_user_defined_sound(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_predefined_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_large_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_small_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_large_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_small_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_var_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_user_prompt_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_ext_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_reused_ext_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_comp_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_obj_dist_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_standard_wvg_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_char_size_wvg_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_ext_obj_data_req_cmd(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_reserved_for_ems(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_email_header(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_hyperlink_format(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_reply_addr(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_enhanced_voice_mail(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_national_lang_single_shift(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_national_lang_locking_shift(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_usim_toolkit_sec_headers(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_reserved_for_future(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_sme_to_sme_specific(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
static int des_iei_sc_specific(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);

/* CDMA */
typedef struct _tpdu_cdma_parm tpdu_cdma_parm;

typedef struct _sms_info sms_info;
typedef struct _sms_addr sms_addr;

typedef int (*sms_dessector)(sms *sms);

struct _sms{
    const char *hex;
    unsigned char *pdu;
    int base, len;

    int cdma, type;
    int smsc;
    int mti;

    unsigned int mr;
    unsigned int vpf;
    unsigned int ref, cnt, seq;
    unsigned int ref_16, cnt_16, seq_16;

    unsigned int src_8, dst_8;
    unsigned int src_16, dst_16;

    /* valid only for specific MTI */
    unsigned int pi:1, pid:1, dcs:1, udl:1;

    /* valid only for COMMAND MTI */
    unsigned int cdl;

    unsigned int ud_len;
    int ud_coding;
    unsigned int udhi:1,compressed:1;

    char *scts;
    sms_addr *oa, *da, *ra;
    char *ud;

    sms_info *smsc_info;
    sms_info *info;
    sms_info *tail;
};


struct _sms_info{
    sms_info *nxt;
    sms_info *prv;

    int offset;
    int len;
    int shift;
    int size;
    const tpdu_parm *handler;
};


enum{
    SMS_DELIVER,
    SMS_DELIVER_REPORT_ERR,
    SMS_DELIVER_REPORT_ACK,
    SMS_STATUS_REPORT,
    SMS_COMMAND,
    SMS_SUBMIT,
    SMS_SUBMIT_REPORT_ERR,
    SMS_SUBMIT_REPORT_ACK,

    /* CDMA */
    SMS_CDMA_PP,
    SMS_CDMA_BC,
    SMS_CDMA_AK,

    SMS_CDMA_DELIVER,
    SMS_CDMA_SUBMIT,
    SMS_CDMA_CANCEL,
    SMS_CDMA_DELIVER_ACK,
    SMS_CDMA_USER_ACK,
    SMS_CDMA_READ_ACK,

    SMS_RESERVED,
};

enum{
    CODING_UNKNOWN,
    CODING_OCTET,
    CODING_IS91,
    CODING_ASC7BIT,
    CODING_GSM7BIT,
    CODING_GSM8BIT,
    CODING_UCS2,
    CODING_UNICODE,
    CODING_SHIFTJIS,
    CODING_IA5,
    CODING_KOREAN,
    CODING_LATIN_HEBREW,
    CODING_LATIN,
};

enum{
    TON_UNKNOWN,
    TON_INTERNATIONAL,
    TON_NATIONAL,
    TON_NETWORK_SPECIFIC,
    TON_SUBSCRIBER,
    TON_ALPHANUMERIC,
    TON_ABBREVIATED,
    /* CDMA */
    TON_IP,
    TON_IEA,                    /* internet mail address */
    TON_RESERVED,
};

enum{
    NPI_UNKNOWN,
    NPI_ISDN_TELEPHONE,
    NPI_DATA,
    NPI_TELEX,
    NPI_NATIONAL,
    NPI_PRIVATE,
    NPI_RESERVED_FOR_CTS,
    NPI_RESERVED,
};

enum{
    VPF_NONE,
    VPF_RELATIVE,
    VPF_ENHANCED,
    VPF_ABSOLUTE,

    /* enhanced sub-vpf */
    VPF_RELATIVE_SEC,
    VPF_RELATIVE_BCD,
    VPF_RESERVED,
};


struct _sms_addr{
    int d_mode, n_mode;          /* CDMA */
    int ton, ton_val, ton_avail; /* type of number */
    int npi, npi_val, npi_avail; /* number plan identification */
    int len;                    /* length of semi-octets */
    char *addr;
};

/*
 * return value:
 * -1: fail to dessect anything
 *  0: successfully dessected something
 * >0: bytes of PDU successfully dessected
 */
typedef int (*tpdu_dess)(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len);
/* TODO: asseble support */
typedef int (*tpdu_asse)(sms *sms, const tpdu_parm *desc, unsigned char *pdu, size_t len);

struct _tpdu_parm{
    int id;                     /* GSM/CDMA */
    int offset;                 /* GSM */
    int len;                    /* GSM/CDMA */
    int shift;                  /* GSM */
    int size;                   /* GSM */
    int pid;                    /* CDMA */
    int spid;                   /* CDMA */
    unsigned int mask;          /* GSM */
    char **desc;                /* GSM */
    tpdu_dess des_func;         /* GSM/CDMA */
    tpdu_asse ass_func;         /* GSM/CDMA */
    int mti;                    /* GSM/CDMA */
};

enum{
    TP_MTI,                     /* message type indication */
    TP_MMS,                     /* more message sent */
    TP_VPF,                     /* validity period format */
    TP_SRI,                     /* status report indication */
    TP_SRR,                     /* status report reqeust */
    TP_MR,                      /* message reference */
    TP_OA,                      /* orignating address */
    TP_DA,                      /* destination address */
    TP_PID,                     /* protocol identifer */
    TP_DCS,                     /* data coding scheme */
    TP_SCTS,                    /* service center time stamp */
    TP_VP,                      /* validity period */
    TP_DT,                      /* discharge time */
    TP_RA,                      /* recipient address */
    TP_ST,                      /* status */
    TP_UDL,                     /* user data length */
    TP_RP,                      /* reply path */
    TP_MN,                      /* message number */
    TP_CT,                      /* command type */
    TP_CDL,                     /* command data length */
    TP_CD,                      /* command data */
    TP_FCS,                     /* failuire cause */
    TP_UDHI,                    /* user data header indication */
    TP_UD,                      /* user data */
    TP_RD,                      /* reject duplicates */
    TP_SRQ,                     /* status report qualifier */
    TP_PI,                      /* parameter indication */

    /* CDMA */
    PID_TSID,                   /* teleservice id */
    PID_SC,                     /* service category */
    PID_OA,                     /* originating addr */
    PID_OSA,                    /* originating subaddr */
    PID_DA,                     /* destination addr */
    PID_DSA,                    /* destination subaddr */
    PID_BRO,                    /* bearer reply option */
    PID_CC,                     /* cause codes */
    PID_BD,                     /* bearer data */

    SPID_MID,                /* message id */
    SPID_UD,                    /* user data */
    SPID_URC,                   /* user response code */
    SPID_MCTS,                  /* message center time stamp */
    SPID_VP_A,                  /* valid period - absolute */
    SPID_VP_R,                  /* valid period - relative */
    SPID_DDT_A,                 /* deferred delivery time - absolute */
    SPID_DDT_R,                 /* deffered delivery time - relative */
    SPID_PI,                    /* priority indicator */
    SPID_PRI,                   /* privacy indicator */
    SPID_RO,                    /* reply option */
    SPID_NM,                    /* number of messages */
    SPID_AMD,                   /* alert on message delivery */
    SPID_LI,                    /* language indicator */
    SPID_CBN,                   /* call back number */
    SPID_MDM,                   /* message display mode */
    SPID_MEUD,                  /* multiple encoding user data */
    SPID_MDI,                   /* message reposit index */
    SPID_SCPD,                  /* service category program data */
    SPID_SCPR,                  /* serivce category program results */
    SPID_MS,                    /* message status */

    /* fake for SMSC header dessect */
    TP_SMSC,
    /* fake for UD headers dessect config */
    TP_UD_HD,

    NUM_TP,
};


struct _des_ctx{
    FILE *out;
    int raw;
    int tp_cfg[NUM_TP];
};


/*
 * return value:
 * -1: fail to dessect anything
 *  0: successfully dessected something
 * >0: bytes of PDU successfully dessected
 */
typedef int (*iei_dess)(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);

typedef int (*pre_dess_ud)(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len);
typedef int (*pst_dess_ud)(sms *sms, des_ctx *cfg, unsigned char *ud);

/* Information Element Identifier */
enum{
    IEI_RESERVED,
    IEI_NOT_USED,
    /* SMS control */
    IEI_CONCAT,
    IEI_SPECIAL,
    IEI_PORT_8BIT,
    IEI_PORT_16BIT,
    IEI_SMSC_CTL,
    IEI_UDH_SRC_IND,
    IEI_CONCAT_16BIT,
    IEI_WIRELESS_CTL,
    /* EMS control */
    IEI_TEXT_FORMAT,
    IEI_PREDEFINED_SOUND,
    IEI_USER_DEFINED_SOUND,
    IEI_PREDEFINED_ANI,
    IEI_LARGE_ANI,
    IEI_SMALL_ANI,
    IEI_LARGE_PIC,
    IEI_SMALL_PIC,
    IEI_VAR_PIC,
    IEI_USER_PROMPT_IND,
    IEI_EXT_OBJ,
    IEI_REUSED_EXT_OBJ,
    IEI_COMP_CTL,
    IEI_OBJ_DIST_IND,
    IEI_STANDARD_WVG_OBJ,
    IEI_CHAR_SIZE_WVG_OBJ,
    IEI_EXT_OBJ_DATA_REQ_CMD,
    IEI_RESERVED_FOR_EMS,
    /* SMS controls */
    IEI_EMAIL_HEADER,
    IEI_HYPERLINK_FORMAT,
    IEI_REPLY_ADDR,
    IEI_ENHANCED_VOICE_MAIL,
    IEI_NATIONAL_LANG_SINGLE_SHIFT,
    IEI_NATIONAL_LANG_LOCKING_SHIFT,
    IEI_USIM_TOOLKIT_SEC_HEADERS,
    IEI_RESERVED_FOR_FUTURE,
    IEI_SME_TO_SME_SPECIFIC,
    IEI_SC_SPECIFIC,

    NUM_IEI,
};

static const char bcd_tbl[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'a', 'b', 'c', 
};


static const char cdma_bcd_tbl[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '*', '#',
};

static const char *gsm_alphabet[] = {
    "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å", /* 0x00 */
    "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\x1B", "Æ", "æ", "ß", "É", /* 0x10 */
    " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", /* 0x20 */
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", /* 0x30 */
    "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", /* 0x40 */
    "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§", /* 0x50 */
    "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", /* 0x60 */
    "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à", /* 0x70 */
};

static const char *gsm_alphabet_ex[128] = {
    [0x0A] = "\n",
    [0x14] = "^",
    [0x28] = "{", [0x29] = "}", [0x2F] = "\\",
    [0x3C] = "[", [0x3D] = "~", [0x3E] = "]",
    [0x40] = "|",
    [0x60] = "€",
};


static const char *mon_tbl[] = {
    "Jan.", "Feb.", "Mar.", "Apr.", "May.", "Jun.", "Jul.", "Aug.", "Sep.", "Oct.", "Nov.", "Dec.",
};

static const char *tpdu_id_name[] = {
    "MESSAGE TYPE(MTI)",
    "MORE MESSAGES TO SEND(MMS)",
    "VALID PERIOD FORMAT(VPF)",
    "STATUS REPORT INDICATION(SRI)",
    "STATUS REPORT REQUEST(SRR)",
    "MESSAGE REFERENCE(MR)",
    "ORIGINATING ADDRESS(OA)",
    "DESTINATION ADDRESS(DA)",
    "PROTOCOL IDENTIFIER(PID)",
    "DATA CODING SCHEME(DCS)",
    "SERVICE CENTRE TIME STAMP(SCTS)",
    "VALID PERIOD(VP)",
    "DISCHARGE TIME(DT)",
    "RECIPIENT ADDRESS(RA)",
    "STATUS(ST)",
    "USER DATA LENGTH(UDL)",
    "REPLY PATH(RP)",
    "MESSAGE NUMBER(MN)",
    "COMMAND TYPE(CT)",
    "COMMAND DATA LENGTH(CDL)",
    "COMMAND DATA(CD)",
    "FAILURE CAUSE(FCS)",
    "USER DATA HEADER INDICATION(UDHI)",
    "USER DATA(UD)",
    "REJECT DUPLICATES(RD)",
    "STATUS REPORT QUALIFIER(SRQ)",
    "PARAMETER INDICATOR(PI)",

    /* CDMA */
    "TELESERVICE ID",
    "SERVICE CATEGORY",
    "ORIGINATING ADDRESS",
    "ORIGNINATIN SUBADDRESS",
    "DESTINATION ADDRESS",
    "DESTINATION SUBADDRESS",
    "BEARER REPLY OPTION",
    "CAUSE CODES",
    "BEARER DATA",

    "MESSAGE ID",
    "USER DATA",
    "USER RESPONSE CODE",
    "MESSAGE CENTER TIME STAMP",
    "VALID PERIOD - ABSOLUTE",
    "VALID PERIOD - RELATIVE",
    "DEFERRED DELIVERY TIME - ABSOLUTE",
    "DEFERRED DELIVERY TIME - RELATIVE",
    "PRIORITY INDICATOR",
    "PRIVACY INDICATOR",
    "REPLY OPTION",
    "NUMBER OF MESSAGES",
    "ALERT ON MESSAGE DELIVERY",
    "LANGUAGE INDICATOR",
    "CALL BACK NUMBER",
    "MESSAGE DISPLAY MODE",
    "MULTIPLE ENCODING USER DATA",
    "MESSAGE REPOSIT INDEX",
    "SERVICE CATEGORY PROGRAM DATA",
    "SERVICE CATEGORY PROGRAM RESULTS",
    "MESSAGE STATUS",

    "SMS CENTRE ADDRESS",
};

static const struct des_ctx_opt{
    char *name;
    char *desc;
}des_ctx_opt[] = {
    {"TP_MTI", "message type indication"},
    {"TP_MMS", "more message sent"},
    {"TP_VPF", "validity period format"},
    {"TP_SRI", "status report indication"},
    {"TP_SRR", "status report reqeust"},
    {"TP_MR", "message reference"},
    {"TP_OA", "orignating address"},
    {"TP_DA", "destination address"},
    {"TP_PID", "protocol identifer"},
    {"TP_DCS", "data coding scheme"},
    {"TP_SCTS", "service center time stamp"},
    {"TP_VP", "validity period"},
    {"TP_DT", "discharge time"},
    {"TP_RA", "recipient address"},
    {"TP_ST", "status"},
    {"TP_UDL", "user data length"},
    {"TP_RP", "reply path"},
    {"TP_MN", "message number"},
    {"TP_CT", "command type"},
    {"TP_CDL", "command data length"},
    {"TP_CD", "command data"},
    {"TP_FCS", "failuire cause"},
    {"TP_UDHI", "user data header indication"},
    {"TP_UD", "user data"},
    {"TP_RD", "reject duplicates"},
    {"TP_SRQ", "status report qualifier"},
    {"TP_PI", "parameter indication"},

    /* CDMA */
    {"PID_TSID", "teleservice id"},
    {"PID_SC", "service category"},
    {"PID_OA", "originating addr"},
    {"PID_OSA", "originating subaddr"},
    {"PID_DA", "destination addr"},
    {"PID_DSA", "destination subaddr"},
    {"PID_BRO", "bearer reply option"},
    {"PID_CC", "cause codes"},
    {"PID_BD", "bearer data"},

    {"SPID_MID", "message id"},
    {"SPID_UD", "user data"},
    {"SPID_URC", "user response code"},
    {"SPID_MCTS", "message center time stamp"},
    {"SPID_VP_A", "valid period - absolute"},
    {"SPID_VP_R", "valid period - relative"},
    {"SPID_DDT_A", "deferred delivery time - absolute"},
    {"SPID_DDT_R", "deffered delivery time - relative"},
    {"SPID_PI", "priority indicator"},
    {"SPID_PRI", "privacy indicator"},
    {"SPID_RO", "reply option"},
    {"SPID_NM", "number of messages"},
    {"SPID_AMD", "alert on message delivery"},
    {"SPID_LI", "language indicator"},
    {"SPID_CBN", "call back number"},
    {"SPID_MDM", "message display mode"},
    {"SPID_MEUD", "multiple encoding user data"},
    {"SPID_MDI", "message reposit index"},
    {"SPID_SCPD", "service category program data"},
    {"SPID_SCPR", "serivce category program results"},
    {"SPID_MS", "message status"},

    /* fake for SMSC header dessect */
    {"TP_SMSC", "SMS center address"},
    /* fake for UD headers dessect config */
    {"TP_UD_HD", "user data headers"},
};


static const char *gsm_sms_type[] = {
    "DELIVER",
    "DELIVER_REPORT_ERR",
    "DELIVER_REPORT_ACK",
    "STATUS_REPORT",
    "COMMAND",
    "SUBMIT",
    "SUBMIT_REPORT_ERR",
    "SUBMIT_REPORT_ACK",
};

/* CDMA */
static const char *cdma_msg_type[] = {
    "Point to Point",
    "Broadcast",
    "Acknowledge",
};

static const char *cdma_sms_type[] = {
    "DELIVER",
    "SUBMIT",
    "CANCEL",
    "DELIVER_ACK",
    "USER_ACK",
    "READ_ACK",
};

static const char *iei_name[] = {
    "Reserved",
    "Value not used to avoid misinterpretation as <LF> character",
    "Concatenated short messages",
    "Special SMS Message Indication",
    "Application port addressing scheme, 8 bit address",
    "Application port addressing scheme, 16 bit address",
    "SMSC Control Parameters",
    "UDH Source Indicator",
    "Concatenated short messages, 16bit",
    "Wireless control message protocol",
    "Text formating",
    "Predefined sound",
    "User defined sound",
    "Predefined animation",
    "Large animation",
    "Smaill animation",
    "Large picture",
    "Smaill picture",
    "Variable picture",
    "User prompt indicator",
    "Extended object",
    "Reused extended object",
    "Conpression control",
    "Object distribution indicator",
    "Standard WVG object",
    "Charactor size WVG object",
    "Extended object data request command",
    "Reserved for future EMS features",
    "RFC 822 E-Mail header",
    "Hyperlink format",
    "Reply address",
    "Enhanced voice mail infomation",
    "National language single shift",
    "National language locking shft",
    "(U)SIM toolkit security headers",
    "Reserved for future use",
    "SME to SME specific use",
    "SC specific use",
};


static const char *ton_tbl[] = {
    "Unknown",
    "International number",
    "National number",
    "Network specific number",
    "Subscriber number",
    "Alphanumeric, (coded according to GSM TS 03.38 7-bit default alphabet)",
    "Abbreviated number",
    "Internet Protocol",
    "Internet Email Address",
    "Reserved for extension",
};

static const char *npi_tbl[] = {
    "Unknown",
    "ISDN/telephone(E.164/E.163)",
    "Data (X.121)",
    "Telex",
    "National",
    "Private",
    "ERMES(ETSI DE/PS 3 01-3)",
    "Reserved for extension",
};


/* message type indication */
static const char *sms_type_mo[] = {
    "SMS-DELIVER-REPORT",       /* 00B */
    "SMS-SUBMIT",               /* 01B */
    "SMS-COMMAND",              /* 10B */
    "<RESERVED>"                /* 11B */
};

static const tpdu_parm mti_desc_mo = {
    .id = TP_MTI,
    .offset = 0,
    .len = 1,
    .shift = 0,
    .size = 2,
    .des_func = NULL,
    .desc = (char **)sms_type_mo,
    .mti = MTI_DELIVER_REPORT_ERR | MTI_DELIVER_REPORT_ACK | MTI_SUBMIT | MTI_COMMAND,
};

/* message type indication */
static const char *sms_type_mt[] = {
    "SMS-DELIVER",              /* 00B */
    "SMS-SUBMIT-REPORT",        /* 01B */
    "SMS-STATUS-REPORT",        /* 10B */
    "<RESERVED>",               /* 11B */
};

static const tpdu_parm mti_desc_mt = {
    .id = TP_MTI,
    .offset = 0,
    .len = 1,
    .shift = 0,
    .size = 2,
    .des_func = NULL,
    .desc = (char **)sms_type_mt,
    .mti = MTI_DELIVER | MTI_SUBMIT_REPORT_ERR | MTI_SUBMIT_REPORT_ACK | MTI_STATUS_REPORT,
};

/* more message to send */
static const char *sms_mms[] = {
    "More messages are waiting for MS in this SC",
    "No more messages are waiting for MS in this SC",
};

static const tpdu_parm mms_desc = {
    .id = TP_MMS,
    .offset = 0,
    .len = 1,
    .shift = 2,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_mms,
    .mti = MTI_DELIVER | MTI_STATUS_REPORT,
};

/* validity period format */
static const char *sms_vpf[] = {
    "Not present",              /* 00B */
    "Enhanced", /* 01B */
    "Relative", /* 10B */
    "Absolute", /* 11B */
};

static const tpdu_parm vpf_desc = {
    .id = TP_VPF,
    .offset = 0,
    .len = 1,
    .shift = 3,
    .size = 2,
    .des_func = des_vpf,
    .desc = (char **)sms_vpf,
    .mti = MTI_SUBMIT,
};

/* status report indication */
static const char *sms_sri[] = {
    "A status report will not be returned to the SME",
    "A status report will be returned to the SME",
};

static const tpdu_parm sri_desc = {
    .id = TP_SRI,
    .offset = 0,
    .len = 1,
    .shift = 5,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_sri,
    .mti = MTI_DELIVER,
};

/* status report request */
static const char *sms_srr[] = {
    "A status report is not requested",
    "A status report is requested",
};

static const tpdu_parm srr_desc = {
    .id = TP_SRR,
    .offset = 0,
    .len = 1,
    .shift = 5,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_srr,
    .mti = MTI_SUBMIT,
};

/* message reference */
static const tpdu_parm mr_desc = {
    .id = TP_MR,
    .offset = 1,
    .len = 1,
    .shift = -1,
    .des_func = des_mr,
    .desc = NULL,
    .mti = MTI_SUBMIT | MTI_STATUS_REPORT | MTI_COMMAND,
};

/* originating address */
static const tpdu_parm oa_desc = {
    .id = TP_OA,
    .offset = 1,
    .len = -1,
    .shift = -1,
    .des_func = des_oa,
    .desc = NULL,
    .mti = MTI_DELIVER,
};

/* destination address */
static const tpdu_parm da_desc_submit = {
    .id = TP_DA,
    .offset = 2,
    .len = -1,
    .shift = -1,
    .des_func = des_da,
    .desc = NULL,
    .mti = MTI_SUBMIT,
};

static const tpdu_parm da_desc_command = {
    .id = TP_DA,
    .offset = 5,
    .len = -1,
    .shift = -1,
    .des_func = des_da,
    .desc = NULL,
    .mti = MTI_COMMAND,
};

/* protocol identifier */
static const tpdu_parm pid_desc_command = {
    .id = TP_PID,
    .offset = 2,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_pid,
    .desc = NULL,
    .mti = MTI_COMMAND,
};

static const tpdu_parm pid_desc_general = {
    .id = TP_PID,
    .offset = -1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_pid,
    .desc = NULL,
    .mti = MTI_DELIVER | MTI_SUBMIT | MTI_DELIVER_REPORT_ACK | MTI_SUBMIT_REPORT_ACK,
};

/* data coding scheme */
static const tpdu_parm dcs_desc_general = {
    .id = TP_DCS,
    .offset = -1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_dcs,
    .desc = NULL,
    .mti = MTI_DELIVER | MTI_SUBMIT | MTI_DELIVER_REPORT_ACK | MTI_SUBMIT_REPORT_ACK | MTI_STATUS_REPORT,
};

/* service centre time stamp */
static const tpdu_parm scts_desc_general = {
    .id = TP_SCTS,
    .offset = -1,
    .len = 7,
    .shift = -1,
    .des_func = des_scts,
    .desc = NULL,
    .mti = MTI_DELIVER | MTI_STATUS_REPORT,
};

static const tpdu_parm scts_desc_submit_report = {
    .id = TP_SCTS,
    .offset = 2,
    .len = 7,
    .shift = -1,
    .des_func = des_scts,
    .desc = NULL,
    .mti = MTI_SUBMIT_REPORT_ACK,
};

/* valid period */
static const tpdu_parm vp_desc = {
    .id = TP_VP,
    .offset = -1,
    .len = -1,
    .shift = -1,
    .des_func = des_vp,
    .desc = NULL,
    .mti = MTI_SUBMIT,
};

/* discharge time */
static const tpdu_parm dt_desc = {
    .id = TP_DT,
    .offset = -1,
    .len = 7,
    .shift = -1,
    .des_func = des_dt,
    .desc = NULL,
    .mti = MTI_STATUS_REPORT,
};

/* recipient address */
static const tpdu_parm ra_desc = {
    .id = TP_RA,
    .offset = 2,
    .len = -1,
    .shift = -1,
    .des_func = des_ra,
    .desc = NULL,
    .mti = MTI_STATUS_REPORT,
};

/* status */
static const tpdu_parm st_desc = {
    .id = TP_ST,
    .offset = -1,
    .len = 1,
    .shift = -1,
    .des_func = des_st,
    .desc = NULL,
    .mti = MTI_STATUS_REPORT,
};

/* user data length */
static const tpdu_parm udl_desc = {
    .id = TP_UDL,
    .offset = -1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_udl,
    .desc = NULL,
    .mti = MTI_DELIVER | MTI_DELIVER_REPORT_ACK | MTI_SUBMIT | MTI_SUBMIT_REPORT_ACK | MTI_STATUS_REPORT,
};


/* reply path */
static const char *sms_rp[] = {
    "No reply path set",
    "Reply path set",
};

static const tpdu_parm rp_desc = {
    .id = TP_RP,
    .offset = 0,
    .len = 1,
    .shift = 6,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_rp,
    .mti = MTI_SUBMIT | MTI_DELIVER,
};

/* message number */
static const tpdu_parm mn_desc = {
    .id = TP_MN,
    .offset = 4,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_mn,
    .desc = NULL,
    .mti = MTI_COMMAND,
};

/* command type */
static const tpdu_parm ct_desc = {
    .id = TP_CT,
    .offset = 3,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_ct,
    .desc = NULL,
    .mti = MTI_COMMAND,
};

/* command data length */
static const tpdu_parm cdl_desc = {
    .id = TP_CDL,
    .offset = -1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_cdl,
    .mti = MTI_COMMAND,
};


/* command data */
static const tpdu_parm cd_desc = {
    .id = TP_CD,
    .offset = -1,
    .len = -1,
    .shift = -1,
    .des_func = des_cd,
    .mti = MTI_COMMAND,
};

/* failure cause */
static const tpdu_parm fcs_desc = {
    .id = TP_FCS,
    .offset = 1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_fcs,
    .mti = MTI_DELIVER_REPORT_ERR | MTI_SUBMIT_REPORT_ERR,
};


/* user data header indication */
static const char *sms_udhi[] = {
    "No user data header",
    "Header contained in user data field",
};

static const tpdu_parm udhi_desc = {
    .id = TP_UDHI,
    .offset = 0,
    .len = 1,
    .shift = 6,
    .size = 1,
    .des_func = des_udhi,
    .desc = (char **)sms_udhi,
    .mti = MTI_SUBMIT | MTI_DELIVER,
};


/* user data */
static const tpdu_parm ud_desc = {
    .id = TP_UD,
    .offset = -1,
    .len = -1,
    .shift = -1,
    .des_func = des_ud,
    .mti = MTI_DELIVER | MTI_DELIVER_REPORT_ACK | MTI_SUBMIT | MTI_SUBMIT_REPORT_ACK | MTI_STATUS_REPORT,
};

/* reject duplicates */
static const char *sms_rd[] = {
    "Not reject duplicating SMS",
    "Reject duplicating SMS",
};

static const tpdu_parm rd_desc = {
    .id = TP_RD,
    .offset = 0,
    .len = 1,
    .shift = 1,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_rd,
    .mti = MTI_SUBMIT,
};


/* status report qualifier */
static const char *sms_srq[] = {
    "SMS status report is the result of a SMS-SUBMIT",
    "SMS status report is the result of an SMS-COMMAND",
};

static const tpdu_parm srq_desc = {
    .id = TP_SRQ,
    .offset = 0,
    .len = 1,
    .shift = 4,
    .size = 1,
    .des_func = NULL,
    .desc = (char **)sms_srq,
    .mti = MTI_STATUS_REPORT,
};

/* parameter indicator */
static const tpdu_parm pi_desc = {
    .id = TP_PI,
    .offset = 1,
    .len = 1,
    .shift = 0,
    .size = 8,
    .des_func = des_pi,
    .desc = NULL,
    .mti = MTI_DELIVER_REPORT_ACK | MTI_SUBMIT_REPORT_ACK,
};


static const tpdu_parm smsc_desc = {
    .id = TP_SMSC,
    .offset = -1,
    .len = -1,
    .shift = -1,
    .size = -1,
    .des_func = des_smsc,
    .desc = NULL,
    .mti = MTI_DELIVER | MTI_STATUS_REPORT,
};

/* CDMA */
#ifdef DEFINE_PID
#undef DEFINE_PID
#endif
#ifdef DEFINE_SPID
#undef DEFINE_SPID
#endif

#define __DEFINE_PID(_id,_len,_pid,_mti,_func)  \
    static int des_pid_##_id(sms *, des_ctx *,  \
                             const tpdu_parm *, \
                             unsigned char *,   \
                             size_t);           \
    static const tpdu_parm pid_##_id##_desc = { \
        .id = PID_##_id,                        \
        .len = _len,                            \
        .shift = -1,                            \
        .pid = _pid,                            \
        .spid = -1,                             \
        .des_func = _func,                      \
        .mti = _mti,                            \
    }

#define DEFINE_PID(_id,_len,_pid,_mti)              \
    __DEFINE_PID(_id,_len,_pid,_mti,des_pid_##_id)

#define DEFINE_SPID(_id,_len,_spid,_mti)            \
    static int des_spid_##_id(sms *, des_ctx *,     \
                              const tpdu_parm *,    \
                              unsigned char *,      \
                              size_t);              \
    static const tpdu_parm spid_##_id##_desc = {    \
        .id = SPID_##_id,                           \
        .len = _len,                                \
        .shift = -1,                                \
        .pid = PID_BD,                              \
        .spid = _spid,                              \
        .des_func = des_spid_##_id,                 \
        .mti = _mti,                                \
    }

DEFINE_PID(TSID, 2, 0, MTI_CDMA_PP);
DEFINE_PID(SC, 2, 1, MTI_CDMA_PP | MTI_CDMA_BC);
DEFINE_PID(OA, -1, 2, MTI_CDMA_PP);
DEFINE_PID(OSA, -1, 3, MTI_CDMA_PP);
DEFINE_PID(DA, -1, 4, MTI_CDMA_PP | MTI_CDMA_AK);
DEFINE_PID(DSA, -1, 5, MTI_CDMA_PP | MTI_CDMA_AK);
DEFINE_PID(BRO, 1, 6, MTI_CDMA_PP);
DEFINE_PID(CC, -1, 7, MTI_CDMA_PP | MTI_CDMA_AK);
__DEFINE_PID(BD, -1, 8, MTI_CDMA_PP | MTI_CDMA_BC,NULL);

DEFINE_SPID(MID, 3, 0, MTI_CDMA);
DEFINE_SPID(UD, -1, 1, MTI_CDMA & ~MTI_CDMA_CANCEL);
DEFINE_SPID(URC, 1, 2, MTI_CDMA | MTI_CDMA_USER_ACK);
DEFINE_SPID(MCTS, 6, 3, MTI_CDMA_DELIVER | MTI_CDMA_USER_ACK | MTI_CDMA_DELIVER_ACK | MTI_CDMA_READ_ACK);
DEFINE_SPID(VP_A, 6, 4, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(VP_R, 1, 5, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(DDT_A, 6, 6, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(DDT_R, 1, 7, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(PI, 1, 8, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(PRI, 1, 9, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(RO, 1, 10, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(NM, 1, 11, MTI_CDMA_DELIVER);
DEFINE_SPID(AMD, 1, 12, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(LI, 1, 13, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(CBN, -1, 14, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT);
DEFINE_SPID(MDM, 1, 15, MTI_CDMA_DELIVER);
DEFINE_SPID(MEUD, -1, 16, MTI_CDMA & ~MTI_CDMA_CANCEL);
DEFINE_SPID(MDI, 2, 17, MTI_CDMA_DELIVER | MTI_CDMA_SUBMIT | MTI_CDMA_USER_ACK | MTI_CDMA_READ_ACK);
DEFINE_SPID(SCPD, -1, 18, MTI_CDMA_DELIVER);
DEFINE_SPID(SCPR, -1, 19, MTI_CDMA_SUBMIT);
DEFINE_SPID(MS, -1, 20, MTI_CDMA_DELIVER_ACK);

#undef DEFINE_PID
#undef DEFINE_SPID

static const tpdu_parm *tpdu_parm_tbl[] = {
    &mti_desc_mo,
    &mti_desc_mt,
    &mms_desc,
    &vpf_desc,
    &sri_desc,
    &srr_desc,
    &mr_desc,
    &oa_desc,
    &da_desc_submit,
    &da_desc_command,
    &pid_desc_command,
    &pid_desc_general,
    &dcs_desc_general,
    &scts_desc_general,
    &scts_desc_submit_report,
    &vp_desc,
    &dt_desc,
    &ra_desc,
    &st_desc,
    &udl_desc,
    &rp_desc,
    &mn_desc,
    &ct_desc,
    &cdl_desc,
    &cd_desc,
    &fcs_desc,
    &udhi_desc,
    &ud_desc,
    &rd_desc,
    &srq_desc,
    &pi_desc,

    &smsc_desc,

    /* CDMA */
    &pid_TSID_desc,
    &pid_SC_desc,
    &pid_OA_desc,
    &pid_OSA_desc,
    &pid_DA_desc,
    &pid_DSA_desc,
    &pid_BRO_desc,
    &pid_CC_desc,
    &pid_BD_desc,

    &spid_MID_desc,
    &spid_UD_desc,
    &spid_URC_desc,
    &spid_MCTS_desc,
    &spid_VP_A_desc,
    &spid_VP_R_desc,
    &spid_DDT_A_desc,
    &spid_DDT_R_desc,
    &spid_PI_desc,
    &spid_PRI_desc,
    &spid_RO_desc,
    &spid_NM_desc,
    &spid_AMD_desc,
    &spid_LI_desc,
    &spid_CBN_desc,
    &spid_MDM_desc,
    &spid_MEUD_desc,
    &spid_MDI_desc,
    &spid_SCPD_desc,
    &spid_SCPR_desc,
    &spid_MS_desc,

    NULL,
};


static const iei_dess iei_dess_tbl[] = {
    des_iei_reserved,
    des_iei_not_used,
    /* SMS CONTROL */
    des_iei_concat,
    des_iei_special,
    des_iei_port_8bit,
    des_iei_port_16bit,
    des_iei_smsc_ctl,
    des_iei_udh_src_ind,
    des_iei_concat_16bit,
    des_iei_wireless_ctl,
    /* EMS control */
    des_iei_text_format,
    des_iei_predefined_sound,
    des_iei_user_defined_sound,
    des_iei_predefined_ani,
    des_iei_large_ani,
    des_iei_small_ani,
    des_iei_large_pic,
    des_iei_small_pic,
    des_iei_var_pic,
    des_iei_user_prompt_ind,
    des_iei_ext_obj,
    des_iei_reused_ext_obj,
    des_iei_comp_ctl,
    des_iei_obj_dist_ind,
    des_iei_standard_wvg_obj,
    des_iei_char_size_wvg_obj,
    des_iei_ext_obj_data_req_cmd,
    des_iei_reserved_for_ems,
    /* SMS controls */
    des_iei_email_header,
    des_iei_hyperlink_format,
    des_iei_reply_addr,
    des_iei_enhanced_voice_mail,
    des_iei_national_lang_single_shift,
    des_iei_national_lang_locking_shift,
    des_iei_usim_toolkit_sec_headers,
    des_iei_reserved_for_future,
    des_iei_sme_to_sme_specific,
    des_iei_sc_specific,
};


static const pre_dess_ud pre_dess_ud_tbl[] = {
    /* TODO: decode PUSH messages here */
};

static const pst_dess_ud pst_dess_ud_tbl[] = {
    /* TODO: decode vCal, vCard here */
};


static inline sms_info *find_sms_info(sms *sms, int id)
{
    sms_info *info;

    for(info = sms->info; info; info = info->nxt)
        if(info->handler->id == id)
            return info;
    return NULL;
}


static inline const tpdu_parm *find_tpdu_desc(sms *sms, int id)
{
    sms_info *info = find_sms_info(sms, id);
    return info ? info->handler : NULL;
}


static inline const tpdu_parm *cdma_tpdu_desc(int mti, int pid, int spid)
{
    const tpdu_parm **p;

    for(p = tpdu_parm_tbl; *p; p++)
        if(((*p)->mti &  mti)
           && pid == (*p)->pid
           && spid == (*p)->spid)
            return *p;
    return NULL;
}

static inline const tpdu_parm *get_tpdu_desc(int mti, int id)
{
    const tpdu_parm **p;

    for(p = tpdu_parm_tbl; *p; p++)
        if(id == (*p)->id && ((*p)->mti &  mti))
            return *p;
    return NULL;
}

static inline void *memdup(const void *src, size_t len)
{
    void *dest = malloc(len);

    if(dest)
        memcpy(dest, src, len);
    return dest;
}

static inline sms_info *new_sms_info(const tpdu_parm *h)
{
    sms_info *info = (sms_info *)malloc(sizeof(sms_info));

    if(info)  {
        info->nxt = info->prv = NULL;

        info->offset = h->offset;
        info->shift = h->shift;
        info->len = h->len;
        info->size = h->size;
        info->handler = h;
    }
    return info;
}

static void delete_info(sms *sms, sms_info *info)
{
    if(info == sms->info)  {
        sms->info = info->nxt;
        if(info->nxt)
            info->nxt->prv = NULL;
        else
            sms->tail = info->prv;
    }else if(info == sms->tail)  {
        sms->tail = info->prv;
        if(info->prv)
            info->prv->nxt = NULL;
    }else  {
        info->prv->nxt = info->nxt;
        info->nxt->prv = info->prv;
    }
    free(info);
}

static inline void append_info(sms *sms, sms_info *info)
{
    if(! sms->info)  {
        sms->tail = sms->info = info;
        info->nxt = info->prv = NULL;
    }else  {
        sms->tail->nxt = info;
        info->prv = sms->tail;
        info->nxt = NULL;
        sms->tail = info;
    }
}


static inline void do_insert(sms_info *prv, sms_info *info)
{
    if(! prv)  {
        info->nxt = info->prv = NULL;
        return;
    }

    info->nxt = prv->nxt;
    if(prv->nxt)
        prv->nxt->prv = info;
    prv->nxt = info;
    info->prv = prv;
}

/* sorted insert based of info->offset */
static void insert_info(sms *sms, sms_info *info)
{
    sms_info *iter;

    info->offset = info->handler->offset;
    info->len = info->handler->len;
    info->shift = info->handler->shift;
    info->size = info->handler->size;

    if(! sms->info)  {
        sms->info = sms->tail = info;
        return;
    }

    if(info->offset < sms->info->offset)  {
        info->nxt = sms->info;
        sms->info->prv = info;
        info->prv = NULL;
        sms->info = info;
        return;
    }

    for(iter = sms->info; iter; iter = iter->nxt)  {
        if(info->offset == iter->offset
           && info->shift > iter->shift)  {
            do_insert(iter, info);
            break;
        }
        if(info->offset > iter->offset
           && (! iter->nxt || info->offset < iter->nxt->offset))  {
            do_insert(iter, info);
            break;
        }
    }

    if(! info->nxt)
        sms->tail = info;
}

static inline void free_infos(sms_info *info)
{
    sms_info *prv;

    for(prv = NULL; info; prv = info, info = info->nxt)  {
        if(prv)  {
            free(prv);
            prv = NULL;
        }
    }

    if(prv)
        free(prv);
}


static inline void free_addr(sms_addr *addr)
{
    if(addr)  {
        if(addr->addr)
            free(addr->addr);
        free(addr);
    }
}

static void sms_clear(sms *sms)
{
    if(sms->pdu)
        free(sms->pdu);

    if(sms->scts)
        free(sms->scts);

    free_addr(sms->oa);
    free_addr(sms->da);
    free_addr(sms->ra);

    if(sms->ud)
        free(sms->ud);

    free_infos(sms->info);
    memset(sms, 0, sizeof(*sms));
}


static inline void init_default_ctx(des_ctx *cfg)
{
    int i = 0;

    cfg->out = stdout;
    cfg->raw = 0;
    for(; i < NUM_TP; i++)
        cfg->tp_cfg[i] = 1;
}

static inline int dehex(char c)
{
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if(c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    return -1;
}

static char *dehex_string(const char *str, int *len)
{
    const char *p;
    char *bin, *q;
    int l;

    if(! str || ! *str || ! len)
        return NULL;

    l = strlen(str) / 2;
    if(! l)
        return NULL;

    *len = l;
    bin = (char *)malloc(l);
    if(! bin)
        return NULL;

    for(p = str, q = bin; l; l--)  {
        *q++ = ((dehex(*p) << 4) | dehex(*(p + 1)));
        p += 2;
    }

    return bin;
}


static void ___hex_dump(int tabs, char *_val, int len)
{
    unsigned char *val = _val;
    int i, j;

    for(i = 0; i < len;)  {
        if(! (i % 16))  {
            for(j = 0; j < tabs; j++)
                printf("\t");
            printf("%-.02X~%.02X  ", i, i + 15);
        }

        if(! (i % 8) && (i % 16))
            printf("  ");

        switch(len - i)  {
        default:
            printf("%02X %02X %02X %02X ", val[i], val[i + 1], val[i + 2], val[i + 3]);
            i += 4;
            break;
        case 2:
        case 3:
            printf("%02X %02X ", val[i], val[i + 1]);
            i += 2;
            break;
        case 1:
            printf("%02X", val[i]);
            i += 1;
            break;
        }

        if(! (i % 16))
            printf("\n");
    }

    if(i % 16)
        printf("\n");
}

static inline void __hex_dump(int tabs, char *val, int len, int cfg)
{
    if(cfg)
        ___hex_dump(tabs, val, len);
}

static inline void hex_dump(char *val, int len, int cfg)
{
    return __hex_dump(1, val, len, cfg);
}

#ifdef HAS_ICONV
static char *utf8(char *text, int len, const char *coding)
{
    char *inbuf, *outbuf, *str;
    size_t in, sz, out, res;
    iconv_t ct;

    if(len < 0)
        in = strlen(text);
    else
        in = (size_t)len;
    sz = out = len = in;

    str = (char *)malloc(sz + 1);
    if(! str)
        return NULL;

    ct = iconv_open("UTF8", coding);
    if(ct == (iconv_t)-1)  {
        printf("Failed encoding convert from %s to UTF8\n", coding);
        free(str);
        return NULL;
    }

    for(inbuf = text, outbuf = str;;)  {
        res = iconv(ct, &inbuf, &in, &outbuf, &out);
        if(res == -1)  {
            if(errno == E2BIG)  {
                out += len;
                sz += len;
                str = (char *)realloc(str, sz + 1);
                if(! str)  {
                    printf("OOM converting encoding!\n");
                    break;
                }
                outbuf = str + sz - out;
                continue;
            }
        }
        break;
    }

    iconv_close(ct);
    str[sz - out] = '\0';
    return str;
}
#else

#define UTF_CODING_INVALID  (-1)
#define UTF_CODING_UTF8     0
#define UTF_CODING_UTF16BE  1
#define UTF_CODING_UTF16LE  2
#define UTF_CODING_UTF32    3

#if __BYTE_ORDER == __BIG_ENDIAN
 #define UTF_CODING_UTF16    UTF_CODING_UTF16BE
#else
 #define UTF_CODING_UTF16    UTF_CODING_UTF16LE
#endif

#define UTF_ERR_OK          0
#define UTF_ERR_BAD_ARG     (-1)
#define UTF_ERR_INCOMPLETE  (-2)
#define UTF_ERR_BAD_CODE    (-3)
#define UTF_ERR_SIZE        (-4)
#define UTF_ERR_NO_SUPPORT  (-5)

typedef struct _utf_coding utf_coding;
typedef int (*utf_encode)(void **buf, size_t *size, unsigned int code_point);
typedef int (*utf_decode)(void **buf, size_t *size, unsigned int *code_point);

struct _utf_coding{
    int coding;
    char *name;
    utf_encode encode;
    utf_decode decode;
};

static int utf_encode_8(void **buf, size_t *size, unsigned int cp);
static int utf_encode_16be(void **buf, size_t *size, unsigned int cp);
static int utf_encode_16le(void **buf, size_t *size, unsigned int cp);

static int utf_decode_8(void **buf, size_t *size, unsigned int *cp);
static int utf_decode_16be(void **buf, size_t *size, unsigned int *cp);
static int utf_decode_16le(void **buf, size_t *size, unsigned int *cp);

static const utf_coding utf_coding_table[] = {
    {UTF_CODING_UTF8, "UTF8", utf_encode_8, utf_decode_8,},
    {UTF_CODING_UTF16BE, "UTF16BE", utf_encode_16be, utf_decode_16be,},
    {UTF_CODING_UTF16LE, "UTF16LE", utf_encode_16le, utf_decode_16le,},
};

static int utf_encode_8(void **buf, size_t *size, unsigned int cp)
{
    unsigned char *p = *buf;
    size_t sz = 0;
    int err = UTF_ERR_OK;

    if(cp > 0x10FFFF)          /* currently UCS stops at 0x10FFFF */
        return UTF_ERR_BAD_CODE;

    if(cp >= 0xD800 && cp <= 0xDFFF) /* fail if fall in UTF16 surrogates */
        return UTF_ERR_BAD_CODE;

    while(*size > 0) {
        if(cp <= 0x7F) {
            *p = cp;
            sz = 1;
            break;
        }

        if(cp <= 0x7FF) {
            if(*size < 2) {
                err = UTF_ERR_SIZE;
                break;
            }

            *p++ = ((cp >> 6) & 0x1F) | 0xC0;
            *p = (cp & 0x3F) | 0x80;
            sz = 2;
            break;
        } else if(cp <= 0xFFFF) {
            if(*size < 3) {
                err = UTF_ERR_SIZE;
                break;
            }

            *p++ = ((cp >> 12) & 0x0F) | 0xE0;
            *p++ = ((cp >> 6) & 0x3F) | 0x80;
            *p = (cp & 0x3F) | 0x80;
            sz = 3;
            break;
        } else if(cp <= 0x1FFFFF) {
            if(*size < 4) {
                err = UTF_ERR_SIZE;
                break;
            }

            *p++ = ((cp >> 18) & 0x07) | 0xF0;
            *p++ = ((cp >> 12) & 0x3F) | 0x80;
            *p++ = ((cp >> 6) & 0x3F) | 0x80;
            *p = (cp & 0x3F) | 0x80;
            sz = 4;
            break;
        }

        err = UTF_ERR_BAD_CODE;
        break;
    }

    *buf = (char *)*buf + sz;
    *size -= sz;
    return err;
}

static void __write_be(void *buf, unsigned short val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    *(unsigned short *)buf = val;
#else
    unsigned char *a = (unsigned char *)buf;

    *a = val >> 8;
    *(a + 1) = val & 0x0F;
#endif
}

static void __write_le(void *buf, unsigned short val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char *a = buf;

    *a = val & 0x0F;
    *(a + 1) = val >> 8;
#else
    *(unsigned short *)buf = val;
#endif
}

static int utf_encode_16(void (*write_short)(void *, unsigned short),
                         void **buf, size_t *size, unsigned int cp)
{
    unsigned short *p = (unsigned short *)*buf;
    size_t sz = 0;
    int err = UTF_ERR_OK;

    if(cp >= 0xD800 && cp <= 0xDFFF) /* fail if fall in UTF16 surrogates */
        return UTF_ERR_BAD_CODE;

    do{
        if(cp < 0x010000) {
            if(*size < 2) {
                err = UTF_ERR_SIZE;
                break;
            }

            write_short(p, cp);
            sz = 2;
            break;
        }

        if(cp > 0x10FFFF) {          /* currently UCS stops at 0x10FFFF */
            err = UTF_ERR_BAD_CODE;
            break;
        }

        if(*size < 4) {
            err = UTF_ERR_SIZE;
            break;
        }

        cp -= 0x010000;
        write_short(p, cp >> 10);
        write_short(p + 1, cp & 0x3FF);
        sz = 4;
        break;
    }while (0);

    *buf = (char *)*buf + sz;
    *size -= sz;
    return err;
}

static int utf_encode_16be(void **buf, size_t *size, unsigned int cp)
{
    return utf_encode_16(__write_be, buf, size, cp);
}

static int utf_encode_16le(void **buf, size_t *size, unsigned int cp)
{
    return utf_encode_16(__write_le, buf, size, cp);
}

static int utf_decode_8(void **buf, size_t *size, unsigned int *cp)
{
    unsigned char *p = *buf;
    size_t sz = 0;
    int err = UTF_ERR_OK;

    while(*size > 0) {
        if(! (*p >> 7)) {       /* ascii code */
            *cp = *p;
            sz = 1;
            break;
        }

#define __UTF8_ACCUM(_p)                                    \
        if((*++(_p) >> 6) != 0x02) {  /* 10XXXXXX format */ \
            err = UTF_ERR_BAD_CODE;                         \
            break;                                          \
        }                                                   \
        *cp = (*cp << 6) | (*(_p) & 0x3F);

        if((*p >> 5) == 0x06) { /* 110XXXXX, 2 byte case */
            if(*size < 2) {
                err = UTF_ERR_INCOMPLETE;
                break;
            }

            *cp = *p & 0x1F;

            __UTF8_ACCUM(p);

            sz = 2;
            break;
        } else if((*p >> 4) == 0x0E) { /* 1110XXXX, 3 byte case */
            if(*size < 3) {
                err = UTF_ERR_INCOMPLETE;
                break;
            }

            *cp = *p & 0x0F;

            __UTF8_ACCUM(p);
            __UTF8_ACCUM(p);

            sz = 3;
            break;
        } else if((*p >> 3) == 0xF0) { /* 11110XXX, 4 byte case */
            if(*size < 4) {
                err = UTF_ERR_INCOMPLETE;
                break;
            }

            *cp = *p & 0x07;

            __UTF8_ACCUM(p);
            __UTF8_ACCUM(p);
            __UTF8_ACCUM(p);

            sz = 4;
            break;
        }
#undef __UTF8_ACCUM

        err = UTF_ERR_BAD_CODE;
        break;
    }

    /* skip surrogates reserved for UTF16, and check UCS tops */
    if(err == UTF_ERR_OK &&
       ((*cp >= 0xD800 && *cp <= 0xDFFF) || *cp > 0x10FFFF)) {
        err = UTF_ERR_BAD_CODE;
    } else {
        *buf = (char *)*buf + sz;
        *size -= sz;
    }
    return err;
}

static unsigned short __read_be(void *buf)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return *(unsigned short *)buf;
#else
    unsigned char *a = buf;

    return (*a << 8 | *(a + 1));
#endif
}

static unsigned short __read_le(void *buf)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char *a = buf;

    return (*a | *(a + 1) << 8);
#else
    return *(unsigned short *)buf;
#endif
}

static int utf_decode_16(unsigned short (*read_short)(void *),
                         void **buf, size_t *size, unsigned int *cp)
{
    unsigned short _cp, surr_high, surr_low;
    size_t sz = 0;
    int err = UTF_ERR_OK;

    if(*size < 2)
        return UTF_ERR_BAD_CODE;

    do{
        _cp = read_short(*buf);
        if(_cp < 0xD800 || _cp > 0xDFFF) { /* BMP plane */
            *cp = _cp;
            sz = 2;
            break;
        }

        /* UTF16/UCS16 extensions */
        if(_cp > 0xDBFF) {       /* high surrogate expected */
            err = UTF_ERR_BAD_CODE;
            break;
        }
        *cp = (_cp - 0xD800) << 10;

        if(_cp < 0xDC00) {       /* low surrogate expected */
            err = UTF_ERR_BAD_CODE;
            break;
        }
        *cp |= (_cp - 0xDC00);

        *cp += 0x010000;

        sz = 4;
        break;
    }while(0);

    *buf = (char *)*buf + sz;
    *size -= sz;
    return err;
}

static int utf_decode_16be(void **buf, size_t *size, unsigned int *cp)
{
    return utf_decode_16(__read_be, buf, size, cp);
}

static int utf_decode_16le(void **buf, size_t *size, unsigned int *cp)
{
    return utf_decode_16(__read_le, buf, size, cp);
}

static int utf_do_convert(const utf_coding *from, void **in, size_t *in_sz,
                          const utf_coding *to, void **out, size_t *out_sz)
{
    unsigned int code_point;
    int err;

    if(! in || ! in_sz || ! out || ! out_sz)
        return UTF_ERR_BAD_ARG;

    while(*in_sz > 0) {
        if((err = from->decode(in, in_sz, &code_point)))
            break;
        if((err = to->encode(out, out_sz, code_point)))
            break;
    }

    return err;
}

static const utf_coding *utf_coding_get(int coding, const char *name)
{
    unsigned int i;

    if(coding != UTF_CODING_INVALID) {
        for(i = 0; i < ARRAYSIZE(utf_coding_table); i++) {
            if(coding == utf_coding_table[i].coding) {
                return &utf_coding_table[i];
            }
        }
    }

    if(name && name[0]) {
        for(i = 0; i < ARRAYSIZE(utf_coding_table); i++) {
            if(! strcasecmp(name, utf_coding_table[i].name)) {
                return &utf_coding_table[i];
            }
        }
    }

    return NULL;
}

static int utf_convert(int from, void **in, size_t *in_sz,
                       int to, void **out, size_t *out_sz)
{
    const utf_coding *fcoding = utf_coding_get(from, NULL);
    const utf_coding *tcoding = utf_coding_get(to, NULL);

    if(! fcoding || ! tcoding)
        return UTF_ERR_NO_SUPPORT;

    return utf_do_convert(fcoding, in, in_sz, tcoding, out, out_sz);
}

static int utf_convert_name(const char *from, void **in, size_t *in_sz,
                            const char *to, void **out, size_t *out_sz)
{
    const utf_coding *fcoding = utf_coding_get(UTF_CODING_INVALID, from);
    const utf_coding *tcoding = utf_coding_get(UTF_CODING_INVALID, to);

    if(! fcoding || ! tcoding)
        return UTF_ERR_NO_SUPPORT;

    return utf_do_convert(fcoding, in, in_sz, tcoding, out, out_sz);
}

static char *utf8(char *text, int len, const char *coding)
{
    char *inbuf, *outbuf, *str;
    size_t in, sz, out, res;

    if(len < 0)
        in = strlen(text);
    else
        in = (size_t)len;
    sz = out = len = in;

    str = (char *)malloc(sz + 1);
    if(! str)
        return NULL;

    for(inbuf = text, outbuf = str;;)  {
        res = utf_convert_name(coding, (void **)&inbuf, &in, "UTF8", (void **)&outbuf, &out);
        if(res == UTF_ERR_SIZE)  {
            out += len;
            sz += len;
            str = (char *)realloc(str, sz + 1);
            if(! str)  {
                printf("OOM converting encoding!\n");
                break;
            }
            outbuf = str + sz - out;
            continue;
        }
        break;
    }

    str[sz - out] = '\0';
    return str;
}
#endif  /* ! HAS_ICONV */

static char *decode_ucs16be(unsigned char *txt, int len)
{
    unsigned short *ucs16 = (unsigned short *)txt;

    /* skipping ending 0xFFFF */
    for(len /= 2; len >= 1 && ucs16[len - 1] == 0xFFFF; len--);
    if(! len)
        return strdup("");
    return utf8((char *)ucs16, len * 2, "UTF16BE");
}


static char *decode_unicode(unsigned char *pdu, int len, int bitoffset)
{
    unsigned short *ucs16, *p;
    unsigned int i, j, c, charoffset, shift;
    char *txt = NULL;

    p = ucs16 = (unsigned short *)malloc(len * sizeof(unsigned short));
    if(p)  {
        for(i = 0, j = len, charoffset = bitoffset / 8, shift = bitoffset % 8;
            j;
            j--, charoffset += 2)  {

            c = (pdu[charoffset] & ((1 << (8 - shift)) - 1));
            c = ((c << 8) | pdu[charoffset + 1]);
            if(shift > 0)
                c = ((c << shift) | (pdu[charoffset + 2] >> (8 - shift)));

            p[i++] = c;
        }
#if __BYTE_ORDER == __BIG_ENDIAN
        txt = utf8((char *)ucs16, len * 2, "UTF16BE");
#else
        txt = utf8((char *)ucs16, len * 2, "UTF16LE");
#endif
        free(ucs16);
    }
    return txt;
}


static char *decode_asc7bit_packed(unsigned char *pdu, int septets, int bitoffset)
{
    unsigned char *str;
    unsigned int i, c, charoffset, shift;

    str = (char *)malloc(septets + 1);
    if(! str)  {
        printf("OOM allocating str:%d!\n", septets + 1);
        return NULL;
    }

    for(i = 0, charoffset = bitoffset / 8, shift = bitoffset % 8;
        septets;
        septets--, bitoffset += 7, charoffset = bitoffset / 8, shift = bitoffset % 8)  {

        if(shift > 1)  {
            c = (pdu[charoffset] & ((1 << (8 - shift)) - 1));
            c = ((c << (shift - 1)) | (pdu[charoffset + 1] >> (9 - shift)));
        }else  {
            c = ((pdu[charoffset] >> (1 - shift)) & 0x7F);
        }

        if(! isprint(c))
            c = ' ';

        str[i++] = c;
    }

    str[i] = '\0';
    return str;    
}


static char *decode_asc7bit_unpacked(unsigned char *pdu, int septets, int bitoffset)
{
    unsigned char *buf, *p;
    unsigned int i, v, charoffset = bitoffset / 8, shift = bitoffset % 8;

    buf = (unsigned char *)malloc(septets + 1);
    if(buf)  {
        if(! shift)  {
            memcpy(buf, pdu + charoffset, septets);
        }else  {
            for(i = 0, p = buf; i < septets; i++, charoffset++)  {
                v = pdu[charoffset] & ((1 << (8 - shift)) - 1);
                v = ((v << shift) | ((pdu[charoffset + 1] >> (8 - shift)) & ((1 << shift) - 1)));
                *p++ = v;
            }
        }
        buf[septets] = '\0';
    }
    return buf;
}


static char *decode_ip_addr(unsigned char *pdu, int bitoffset)
{
    unsigned int v, charoffset = bitoffset / 8, shift = bitoffset % 8;
    unsigned char *buf = NULL, *p = (unsigned char *)&v;

    if(! shift)
        v = pdu[charoffset++];
    else
        v = pdu[charoffset++] & ((1 << (8 - shift)) - 1);
    v = (v << 8) | pdu[charoffset++];
    v = (v << 8) | pdu[charoffset++];
    if(! shift)
        v = (v << 8) | pdu[charoffset++];
    else
        v = (v << shift) | ((pdu[charoffset] >> (8 - shift)) & ((1 << shift) - 1));

#if __BYTE_ORDER == __BIG_ENDIAN
    asprintf(&buf, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
#else
    asprintf(&buf, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
#endif
    return buf;
}

static char *decode_gsm7bit_packed(unsigned char *pdu, int septets, int padingbits)
{
    char *str, *p;
    int esc = 0, c, bitoffset, charoffset, shift;
    int i, sz = septets;

    str = (char *)malloc(sz + 1);
    if(! str)  {
        printf("OOM allocating str:%d!\n", sz + 1);
        return NULL;
    }

    for(i = 0, bitoffset = padingbits, charoffset = 0, shift = padingbits;
        septets;
        septets--, bitoffset += 7, charoffset = bitoffset / 8, shift = bitoffset % 8)  {

        c = ((pdu[charoffset] >> shift) & 0x7F);
        if(shift > 1)
            c |= ((pdu[charoffset + 1] << (8 - shift)) & 0x7F);

        if(c == 0x1B)  {
            esc = 1;
            continue;
        }

        if(i + 4 > sz)  {
            sz += (septets / 2 ? : 4);
            p = (char *)realloc(str, sz + 1);
            if(! p)  {
                printf("OOM realloc str!\n");
                str[i] = '\0';
                return str;
            }
            str = p;
        }

        if(esc)  {
            /* fake a invalid escaped char as a space */
            if(! gsm_alphabet_ex[c])
                str[i++] = ' ';
            else  {
                strcpy(str + i, gsm_alphabet_ex[c]);
                i += strlen(gsm_alphabet_ex[c]);
            }
            esc = 0;
            continue;
        }

        strcpy(str + i, gsm_alphabet[c]);
        i += strlen(gsm_alphabet[c]);
    }

    str[i] = '\0';
    return str;    
}

static char *decode_gsm8bit_unpacked(unsigned char *pdu, int len)
{
    char *str, *p;
    int esc, c, i, j, sz = len;

    str = (char *)malloc(sz + 1);
    if(! str)  {
        printf("OOM allocating str:%d!\n", sz + 1);
        return NULL;
    }

    for(esc = 0, i = 0, j = 0; j < len; j++)  {
        c = pdu[j] & 0x7F;
        if(c == 0x1B)  {
            esc = 1;
            continue;
        }

        if(i + 4 > sz)  {
            sz += (len / 2 ? : 4);
            p = (char *)realloc(str, sz + 1);
            if(! str)  {
                printf("OOM realloc str!\n");
                str[i] = '\0';
                return str;
            }
            str = p;
        }

        if(esc)  {
            /* fake a invalid escaped char as a space */
            if(! gsm_alphabet_ex[c])
                str[i++] = ' ';
            else  {
                strcpy(str + i, gsm_alphabet_ex[c]);
                i += strlen(gsm_alphabet_ex[c]);
            }
            esc = 0;
            continue;
        }

        strcpy(str + i, gsm_alphabet[c]);
        i += strlen(gsm_alphabet[c]);
    }

    str[i] = '\0';
    return str;
}

static char *decode_ucs2(char *pdu, char base, int len)
{
    char *ret, *tmp;
    size_t sz = len;
    int i, j, m;

    ret = (char *)malloc(sz + 1);
    if(! ret)  {
        printf("OOM alloc buffer!\n");
        return NULL;
    }

    for(i = 0, j = 0; i < len;)  {
        if(j == sz)  {
            sz += len;
            ret = (char *)realloc(ret, sz);
            if(! ret)  {
                printf("OOM enlarge buffer\n");
                break;
            }
        }

        if(pdu[i] < 0)
            ret[j++] = (char)(base + (pdu[i++] & 0x7F));

        for(m = i; m < len && pdu[m] >= 0; m++)
            ;

        tmp = decode_gsm8bit_unpacked(pdu + i, m - i);
        if(tmp)  {
            int l = strlen(tmp);

            if(l > sz - j)  {
                sz += l;
                ret = (char *)realloc(ret, sz);
                if(! ret)  {
                    printf("OOM enlarge buffer\n");
                    break;
                }
            }
            strcpy(ret + j, tmp);
            j += l;
            free(tmp);
        }
        i += m;
    }

    ret[j] = '\0';
    return ret;
}

static char *decode_adn(unsigned char *pdu, int len)
{
    int i = 0, l = 0, ucs2 = 0;
    char base = '\0';

    if(! len)
        return strdup("");

    if(len >= 1 && pdu[i] == 0x80)
        return decode_ucs16be(pdu + 1, len - 1);

    if(len >= 3 && pdu[i] == 0x81)  {
        l = pdu[i + 1] & 0xff;
        if(l > len - 3)
            l = len - 3;
        base = (char)((pdu[i + 2] & 0xff) << 7);
        i += 3;
        ucs2 = 1;
    }else if(len >= 4 && pdu[i] == 0x82)  {
        l = pdu[i + 1] & 0xff;
        if(l > len - 4)
            l = len - 4;
        base = (char)(((pdu[i + 2] & 0xff) << 8) | (pdu[i + 3] & 0xff));
        i += 4;
        ucs2 = 1;
    }

    if(ucs2)
        return decode_ucs2(pdu + i, base, len - i);

    return decode_gsm8bit_unpacked(pdu, len);
}

static inline int decode_bcd(unsigned char pdu)
{
    int ret = 0;

    if((pdu & 0xF0) <= 0x90)
        ret = (pdu >> 4) & 0x0F;
    if((pdu & 0x0F) <= 9)
        ret += (pdu & 0x0F) * 10;

    return ret;
}


static inline int decode_bcd_cdma(unsigned char pdu)
{
    int ret = 0;

    if((pdu & 0x0F) <= 9)
        ret = pdu & 0x0F;
    if((pdu & 0xF0) <= 0x90)
        ret += ((pdu >> 4) & 0x0F) * 10;

    return ret;
}


/* FIXME:modify num according num type */
static unsigned char *decode_bcd_num(unsigned char *pdu, int sz)
{
    unsigned char *num = (char *)malloc(sz + 1), idx;
    int  i;

    if(num)  {
        for(i = 0; i < sz;)  {
            idx = pdu[i / 2] & 0x0F;
            if(idx == 0x0F)
                break;
            num[i++] = bcd_tbl[idx];

            if(i == sz)
                break;

            idx = (pdu[i / 2] >> 4) & 0x0F;
            if(idx == 0x0F)
                break;
            num[i++] = bcd_tbl[idx];
        }
        num[i] = '\0';
    }

    return num;
}


static unsigned char *decode_bcd_num_cdma(unsigned char *pdu, int sz, int bitoffset)
{
    unsigned char *buf, *p, *num;
    unsigned int i, v, len, charoffset = bitoffset / 8, shift = bitoffset % 8;

    if(! shift)  {
        buf = pdu + charoffset;
    }else  {
        buf = (unsigned char *)alloca((sz + 1) / 2);
        for(i = 0, p = buf, len = (sz + 1) / 2; i < len; i++, charoffset++)  {
            v = pdu[charoffset] & ((1 << (8 - shift)) - 1);
            v = ((v << shift) | ((pdu[charoffset + 1] >> (8 - shift)) & ((1 << shift) - 1)));
            *p++ = v;
        }
    }

    num = (unsigned char *)malloc(sz + 1);
    if(num)  {
        for(i = 0; i < sz;)  {
            v = ((buf[i / 2] >> 4) & 0x0F) - 1;
            num[i++] = (v < ARRAYSIZE(cdma_bcd_tbl)) ? cdma_bcd_tbl[v] : 'x';

            if(i == sz)
                break;

            v = (buf[i / 2] & 0x0F) - 1;
            num[i++] = (v < ARRAYSIZE(cdma_bcd_tbl)) ? cdma_bcd_tbl[v] : 'x';
        }
        num[i] = '\0';
    }

    return num;
}


static int __des_addr(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len, sms_addr **_addr)
{
    unsigned char _addr_len, _toa, _ton, _npi;
    int ton, npi, npi_avail;
    char *num;
    sms_addr *addr;
    int pdu_len;

    if(len < 2)
        return -1;

    _addr_len = pdu[0];         /* length of semi-octets */
    pdu_len = (_addr_len + 1) / 2 + 2;
    if(len < pdu_len || pdu_len > 12)  {
        DES_PRINT("[ERR]invalid addr parm\n");
        return -1;
    }
    _toa = pdu[1];
    _npi = _toa & 0xF;
    _ton = (_toa >> 4) & 0x7;

    switch(_ton)  {
    case 0x00:
        ton = TON_UNKNOWN;
        break;
    case 0x01:
        ton = TON_INTERNATIONAL;
        break;
    case 0x02:
        ton = TON_NATIONAL;
        break;
    case 0x03:
        ton = TON_NETWORK_SPECIFIC;
        break;
    case 0x04:
        ton = TON_SUBSCRIBER;
        break;
    case 0x05:
        ton = TON_ALPHANUMERIC;
        break;
    case 0x06:
        ton = TON_ABBREVIATED;
        break;
    default:
        ton = TON_RESERVED;
        break;
    };

    switch(_npi)  {
    case 0x00:
        npi = NPI_UNKNOWN;
        break;
    case 0x01:
        npi = NPI_ISDN_TELEPHONE;
        break;
    case 0x03:
        npi = NPI_DATA;
        break;
    case 0x04:
        npi = NPI_TELEX;
        break;
    case 0x08:
        npi = NPI_NATIONAL;
        break;
    case 0x09:
        npi = NPI_PRIVATE;
        break;
    case 0x0A:
        npi = NPI_RESERVED_FOR_CTS;
        break;
    default:
        npi = NPI_RESERVED;
        break;
    }

    npi_avail = (ton == TON_UNKNOWN || ton == TON_INTERNATIONAL || ton == TON_NATIONAL);
    if(ton == TON_ALPHANUMERIC)
        num = decode_gsm7bit_packed(pdu + 2, _addr_len * 4 / 7, 0);
    else
        num = decode_bcd_num(pdu + 2, _addr_len);

    addr = (sms_addr *)malloc(sizeof(sms_addr));
    if(addr)  {
        addr->ton = ton;
        addr->ton_val = _ton;
        addr->ton_avail = 1;

        addr->npi = npi;
        addr->npi_val = _npi;
        addr->npi_avail = npi_avail;

        addr->addr = num;

        *_addr = addr;
        return pdu_len;
    }

    *_addr = NULL;
    if(num)
        free(num);
    /* just skip if anything failed */
    return pdu_len;
}

static int des_vpf(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    switch((pdu[0] >> 3) & 0x03)  {
    case 0:
        sms->vpf = VPF_NONE;
        break;
    case 1:
        sms->vpf = VPF_ENHANCED;
        break;
    case 2:
        sms->vpf = VPF_RELATIVE;
        break;
    case 3:
        sms->vpf = VPF_ABSOLUTE;
        break;
    }
    return 0;
}


static int des_mr(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms->mr = pdu[0];
    DES_PRINT("\tREFERENCE NUMBER:%u\n", (int)pdu[0]);
    return 1;
}

static const char *tel_dev[] = {
    "Implicit - device type is specific to this SC, or can be concluded on the basis of the address",
    "Telex (or teletex reduced to telex format)",
    "Group 3 telefax",
    "Group 4 telefax",
    "Voice telephone (i.e. conversion to speech)",
    "ERMES (European Radio Messaging System)",
    "National Paging system (known to the SC)",
    "Videotex (T.100/T.101)",
    "Teletex, carrier unspecified",
    "Teletex, in PSPDN",
    "Teletex, in CSPDN",
    "Teletex, in analog PSTN",
    "Teletex, in digital ISDN",
    "UCI (Universal Computer Interface, ETSI DE/PS 3 01-3)",
    [0x0E ... 0x0F] = "Reserved",
    "A message handling facility (known to the SC)",
    "Any public X.400-based message handling system",
    "Internet Electronic Mail",
    [0x13 ...0x17] = "Reserved",
    [0x18 ... 0x1E] = "Values specific to each SC, usage based on mutual agreement between the SME and the SC (7 combinations available for each SC)",
    "A GSM mobile station. The SC converts the SM from the received TP-Data-Coding-Scheme to any data coding scheme supported by that MS (e.g. the default).",
};

static const char *msg_typ[] = {
    "Short Message Type 0",
    "Replace Short Message Type 1",
    "Replace Short Message Type 2",
    "Replace Short Message Type 3",
    "Replace Short Message Type 4",
    "Replace Short Message Type 5",
    "Replace Short Message Type 6",
    "Replace Short Message Type 7",
    [0x08 ... 0x1E] = "Reserved",
    "Return Call Message",
    [0x20 ... 0x3D] = "Reserved",
    "ME De-personalization Short Message",
    "SIM Data download",
};

static int des_pid(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned char domain, interworking, dev, typ;

    BUILD_FAIL_IF(32 != ARRAYSIZE(tel_dev));
    BUILD_FAIL_IF(0x40 != ARRAYSIZE(msg_typ));

    domain = (pdu[0] >> 6) & 0x03;
    if(domain == 0x02)  {
        DES_PRINT("\t<Reserved(0x%X)>\n", pdu[0]);
    }else if(domain == 0x03)  {
        DES_PRINT("\t<For SC specific use(0x%X)>\n", pdu[0]);
    }else if(domain == 0x00) {
        interworking = pdu[0] & 0x20;
        dev = pdu[0] & 0x1F;

        if(! interworking)
            DES_PRINT("\t<No interworking, but SME-to-SME protocol(0x%X)>\n", dev);
        else  {
            DES_PRINT("\tTelematic Interworking\n");
            DES_PRINT("\tTelematic Deivce(0x%X):%s\n", dev, tel_dev[dev]);
        }
    }else  {
        typ = pdu[0] & 0x3F;

        DES_PRINT("Short Message Type(0x%X):%s\n", typ, msg_typ[typ]);
    }

    return 1;
}

static int des_dcs(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned char grp = (pdu[0] >> 6) & 0x03;

    if(grp == 0x00)  {
        DES_PRINT("\tGeneral Data Coding Indication\n");
        if(pdu[0] & 0x20)  {
            sms->compressed = 1;
            DES_PRINT("\tText is Compressed\n");
        }
        if(pdu[0] & 0x10)  {
            switch(pdu[0] & 0x03)  {
            case 0:
                DES_PRINT("\tMESSAGE CLASS:0\n", 0);
                break;
            case 1:
                DES_PRINT("\tMESSAGE CLASS:1, ME-Specific\n");
                break;
            case 2:
                DES_PRINT("\tMESSAGE CLASS:2, SIM specific message\n");
                break;
            case 3:
                DES_PRINT("\tMESSAGE CLASS:3, TE Specific\n");
                break;
            }
        }

        switch((pdu[0] >> 2) & 0x03)  {
        case 0:
            sms->ud_coding = CODING_GSM7BIT;
            DES_PRINT("\tENCODING: Default alphabet\n");
            break;
        case 1:
            sms->ud_coding = CODING_GSM8BIT;
            DES_PRINT("\tENCODING: 8 bit data\n");
            break;
        case 2:
            sms->ud_coding = CODING_UCS2;
            DES_PRINT("\tENCODING: UCS2(16bit)\n");
            break;
        default:
            sms->ud_coding = CODING_UNKNOWN;
            DES_PRINT("\tENCODING: Reserved\n");
            break;
        }
        return 1;
    }

    grp = (pdu[0] >> 4) & 0x0F;
    if(grp >= 0x04 && grp <= 0x0B)  {
        DES_PRINT("\tReserved Coding Groups(0x%X)\n", grp);
        return 1;
    }

    if(grp == 0x0C || grp == 0x0D || grp == 0x0E)  {
        DES_PRINT("\tMessage Waiting Indication Group:%s\n", (grp & 0x03) ? "Store Message" : "Discard Message");
        DES_PRINT("\tINDICATION:%s\n", (pdu[0] & 0x08) ? "Active" : "Inactive");
        switch(pdu[0] & 0x03)  {
        case 0:
            DES_PRINT("\tINDICATION TYPE: Voicemail Message Waiting");
            break;
        case 1:
            DES_PRINT("\tINDICATION TYPE: Fax Message Waiting");
            break;
        case 2:
            DES_PRINT("\tINDICATION TYPE: Electronic Mail Message Waiting");
            break;
        default:
            DES_PRINT("\tINDICATION TYPE: Other Message Waiting");
            break;
        }
        if(grp == 0x0E)  {
            sms->ud_coding = CODING_UCS2;
            DES_PRINT("\tENCODING: UCS2(16bit)\n");
        }else  {
            sms->ud_coding = CODING_GSM7BIT;
            DES_PRINT("\tENCODING: Default alphabet\n");
        }
        return 1;
    }

    if(grp == 0x0F)  {
        switch(pdu[0] & 0x03)  {
        case 0:
            DES_PRINT("\tMESSAGE CLASS:0\n", 0);
            break;
        case 1:
            DES_PRINT("\tMESSAGE CLASS:1, ME-Specific\n");
            break;
        case 2:
            DES_PRINT("\tMESSAGE CLASS:2, SIM specific message\n");
            break;
        case 3:
            DES_PRINT("\tMESSAGE CLASS:3, TE Specific\n");
            break;
        }

        if(pdu[0] & 0x04)  {
            sms->ud_coding = CODING_GSM8BIT;
            DES_PRINT("\tENCODING: 8 bit data\n");
        }else  {
            sms->ud_coding = CODING_GSM7BIT;
            DES_PRINT("\tENCODING: Default alphabet\n");
        }
    }

    return 1;
}


/* FIXME: print time in current locale */
static int des_scts(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int y, m, d, h, min, sec, z;
    char z_str[20];

    if(len < 7)  {
        DES_PRINT("[ERR]Invalid SCTS PDU\n");
        return -1;
    }

    y = decode_bcd(pdu[0]);
    y += (y >= 90) ? 1900 : 2000;
    m = decode_bcd(pdu[1]);
    d = decode_bcd(pdu[2]);
    h = decode_bcd(pdu[3]);
    min = decode_bcd(pdu[4]);
    sec = decode_bcd(pdu[5]);
    z = decode_bcd(pdu[6] & ~0x08);

    sprintf(z_str, "%d", z / 4);
    switch(z % 4)  {
    case 1:
        strcat(z_str, ".25");
        break;
    case 2:
        strcat(z_str, ".50");
        break;
    case 3:
        strcat(z_str, ".75");
        break;
    default:
        break;
    }

    if(sms->scts)
        free(sms->scts);
    asprintf(&sms->scts, "%d-%d-%d %02d:%02d:%02d GMT%c%sH",
             y, m, d, h, min, sec, (pdu[6] & 0x08) ? '-' : '+', z_str);
    DES_PRINT("\tTIME STAMP:%s\n", sms->scts ? : "<OOM Printing!>");
    return 7;
}


static int __des_vp_relative(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu)
{
    char w[20], d[20], h[20], m[20];
    int val = pdu[0];

    if(val <= 143)  {
        int _h = ((val + 1) * 5) / 60;
        int _m = ((val + 1) * 5) % 60;

        if(_h)
            sprintf(h, "%d Hour(s)", _h);
        if(_m)
            sprintf(m, " %d Minute(s)", _m);
        DES_PRINT("\tVALID THROUGH:%s%s\n", _h ? h : "", _m ? m : "");
    }else if(val <= 167)  {
        int _h = 12 + (val - 143) * 30 / 60;
        int _m = (val - 143) * 30 % 60;

        if(_h)
            sprintf(h, "%d Hour(s)", _h);
        if(_m)
            sprintf(m, " %d Minute(s)", _m);
        DES_PRINT("\tVALID THROUGH:%s%s\n", _h ? h : "", _m ? m : "");
    }else if(val <= 196)  {
        DES_PRINT("\tVALID THROUGH:%d Day(s)\n", val - 166);
    }else  {
        DES_PRINT("\tVALID THROUGH:%d Week(s)\n", val - 192);
    }
    return 1;
}


static int des_vp(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    if(sms->vpf == VPF_NONE)
        /* should not be called */
        return -1;

    if(sms->vpf == VPF_RELATIVE)
        return __des_vp_relative(cfg, desc, pdu);

    if(sms->vpf == VPF_ABSOLUTE)  {
        int y, m, d, h, min, sec, z;
        char z_str[20];

        if(len < 7)  {
            DES_PRINT("[ERR]Invalid VP PDU\n");
            return -1;
        }

        y = decode_bcd(pdu[0]);
        y += (y >= 90) ? 1900 : 2000;
        m = decode_bcd(pdu[1]);
        d = decode_bcd(pdu[2]);
        h = decode_bcd(pdu[3]);
        min = decode_bcd(pdu[4]);
        sec = decode_bcd(pdu[5]);
        z = decode_bcd(pdu[6] & ~0x08);

        sprintf(z_str, "%d", z / 4);
        switch(z % 4)  {
        case 1:
            strcat(z_str, ".25");
            break;
        case 2:
            strcat(z_str, ".50");
            break;
        case 3:
            strcat(z_str, ".75");
            break;
        default:
            break;
        }

        DES_PRINT("\tVALID BEFORE:%d-%d-%d %02d:%02d:%02d GMT%c%sH\n",
                  y, m, d, h, min, sec, (pdu[6] & 0x08) ? '-' : '+', z_str);
        return 7;
    }

    if(sms->vpf == VPF_ENHANCED)  {
        int fmt = VPF_NONE;

        if(len < 7)  {
            DES_PRINT("[ERR]Invalid VP PDU\n");
            return -1;
        }

        DES_PRINT("\tVALIDITY EXTENSION AVAIL:%s\n", (pdu[0] & 0x80) ? "YES" : "NO");
        DES_PRINT("\tSINGLE SHOT SMS:%s\n", (pdu[0] & 0x40) ? "YES" : "NO");
        switch(pdu[0] & 0x07)  {
        case 0:
            fmt = VPF_NONE;
            break;
        case 1:
            fmt = VPF_RELATIVE;
            break;
        case 2:
            fmt = VPF_RELATIVE_SEC;
            break;
        case 3:
            fmt = VPF_RELATIVE_BCD;
            break;
        default:
            fmt = VPF_RESERVED;
            break;
        }

        if(fmt == VPF_NONE)  {
            DES_PRINT("\tENHANCED VALIDITY PERIOD FORMAT:Not Specified\n");
            DES_PRINT("\t<Unable To Dessect Enhanced VP>\n");
            HEX_DUMP(pdu + 1, 6);
        }else if(fmt == VPF_RELATIVE)  {
            DES_PRINT("\tENHANCED VALIDITY PERIOD FORMAT:Relative\n");
            __des_vp_relative(cfg, desc, pdu + 1);
        }else if(fmt == VPF_RELATIVE_SEC)  {
            DES_PRINT("\tENHANCED VALIDITY PERIOD FORMAT:Relative in Seconds\n");
            DES_PRINT("\tVALID THROUGH:%d Second(s)%s\n", pdu[1], pdu[1] ? "" : "(Invalid)");
        }else  {
            DES_PRINT("\tENHANCED VALIDITY PERIOD FORMAT:Reserved\n");
            DES_PRINT("\t<Unable To Dessect Enhanced VP>\n");
            HEX_DUMP(pdu + 1, 6);
        }
        return 7;
    }

    printf("VPF Unknown, Can't Dessect VP\n");
    return -1;
}

static int des_addr(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len, sms_addr **_addr)
{
    int ton, npi, res;
    sms_addr *addr;

    res = __des_addr(cfg, desc, pdu, len, &addr);
    if(res > 0 && addr)  {
        DES_PRINT("\tTYPE   :%s(0x%X)\n", ton_tbl[addr->ton], addr->ton_val);
        if(addr->npi_avail)
            DES_PRINT("\tPLAN ID:%s(0x%X)\n", npi_tbl[addr->npi], addr->npi_val);
        DES_PRINT("\tNUMBER :%s\n", addr->addr ?: "<Invalid or Fail to Parse>");
    }else  {
        DES_PRINT("\t<Invalid Address or Fail to Parse>\n");
    }

    *_addr = addr;
    return res;
}


static int des_oa(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int res;
    sms_addr *addr;

    res = des_addr(cfg, desc, pdu, len, &addr);
    if(res > 0)  {
        if(sms->oa)
            free_addr(sms->oa);
        sms->oa = addr;
    }
    return res;
}

static int des_da(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int res;
    sms_addr *addr;

    res = des_addr(cfg, desc, pdu, len, &addr);
    if(res > 0)  {
        if(sms->da)
            free_addr(sms->da);
        sms->da = addr;
    }
    return res;
}

static int des_dt(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int y, m, d, h, min, sec, z;
    char z_str[20];

    if(len < 7)  {
        DES_PRINT("[ERR]Invalid DT PDU\n");
        return -1;
    }

    y = decode_bcd(pdu[0]);
    y += (y >= 90) ? 1900 : 2000;
    m = decode_bcd(pdu[1]);
    d = decode_bcd(pdu[2]);
    h = decode_bcd(pdu[3]);
    min = decode_bcd(pdu[4]);
    sec = decode_bcd(pdu[5]);
    z = decode_bcd(pdu[6] & ~0x08);

    sprintf(z_str, "%d", z / 4);
    switch(z % 4)  {
    case 1:
        strcat(z_str, ".25");
        break;
    case 2:
        strcat(z_str, ".50");
        break;
    case 3:
        strcat(z_str, ".75");
        break;
    default:
        break;
    }

    DES_PRINT("\tDISCHARGE TIME:%d-%d-%d %02d:%02d:%02d GMT%c%sH\n",
              y, m, d, h, min, sec, (pdu[6] & 0x08) ? '-' : '+', z_str);
    return 7;
}

static int des_ra(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int res;
    sms_addr *addr;

    res = des_addr(cfg, desc, pdu, len, &addr);
    if(res > 0)  {
        if(sms->ra)
            free_addr(sms->ra);
        sms->ra = addr;
    }
    return res;
}

static int des_st(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    if(pdu[0] & 0x80)  {
        DES_PRINT("\t<Reserved Status Value(0x%X)>\n", pdu[0]);
        return 1;
    }

    switch((pdu[0] >> 4) & 0x07)  {
    case 0x00:
        DES_PRINT("\t<Short Message Transaction Completed>\n");
        break;
    case 0x02:
        DES_PRINT("\t<Temporary Error, SC Still Trying To Transfer SM>\n");
        break;
    case 0x04:
        DES_PRINT("\t<Permanent Error, SC Not Making Any More Transfer Attempts>\n");
        break;
    case 0x06:
        DES_PRINT("\t<Temporary Error, SC Not Making Any More Transfer Attempts>\n");
        break;
    default:
        break;
    }

    switch(pdu[0] & 0x7F)  {
    case 0x00:
        DES_PRINT("\tSTATUS:Short message received by the SME\n");
        break;
    case 0x01:
        DES_PRINT("\tSTATUS:Short message forwarded by the SC to "
               "the SME but the SC is unable to confirm delivery\n");
        break;
    case 0x02:
        DES_PRINT("\tSTATUS:Short message replaced by the SC\n");
    case 0x03 ... 0x0F:
        DES_PRINT("\tSTATUS:Reserved(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x10 ... 0x1F:
        DES_PRINT("\tSTATUS:Values specific to each SC(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x20:
        DES_PRINT("\tSTATUS:Congestion\n");
        break;
    case 0x21:
        DES_PRINT("\tSTATUS:SME busy\n");
        break;
    case 0x22:
        DES_PRINT("\tSTATUS:No response from SME\n");
        break;
    case 0x23:
        DES_PRINT("\tSTATUS:Service rejected\n");
        break;
    case 0x24:
        DES_PRINT("\tSTATUS:Quality of service not available\n");
        break;
    case 0x25:
        DES_PRINT("\tSTATUS:Error in SME\n");
        break;
    case 0x26 ... 0x2F:
        DES_PRINT("\tSTATUS:Reserved(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x30 ... 0x3F:
        DES_PRINT("\tSTATUS:Values specific to each SC(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x40:
        DES_PRINT("\tSTATUS:Remote procedure error\n");
        break;
    case 0x41:
        DES_PRINT("\tSTATUS:Incompatible destination\n");
        break;
    case 0x42:
        DES_PRINT("\tSTATUS:Connection rejected by SME\n");
        break;
    case 0x43:
        DES_PRINT("\tSTATUS:Not obtainable\n");
        break;
    case 0x44:
        DES_PRINT("\tSTATUS:Quality of service not available\n");
        break;
    case 0x45:
        DES_PRINT("\tSTATUS:No interworking available\n");
        break;
    case 0x46:
        DES_PRINT("\tSTATUS:SM Validity Period Expired\n");
        break;
    case 0x47:
        DES_PRINT("\tSTATUS:SM Deleted by originating SME\n");
        break;
    case 0x48:
        DES_PRINT("\tSTATUS:SM Deleted by SC Administration\n");
        break;
    case 0x49:
        DES_PRINT("\tSTATUS:SM does not exist\n");
        break;
    case 0x4A ... 0x4F:
        DES_PRINT("\tSTATUS:Reserved(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x50 ... 0x5F:
        DES_PRINT("\tSTATUS:Values specific to each SC(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x60:
        DES_PRINT("\tSTATUS:Congestion\n");
        break;
    case 0x61:
        DES_PRINT("\tSTATUS:SME busy\n");
        break;
    case 0x62:
        DES_PRINT("\tSTATUS:No response from SME\n");
        break;
    case 0x63:
        DES_PRINT("\tSTATUS:Service rejected\n");
        break;
    case 0x64:
        DES_PRINT("\tSTATUS:Quality of service not available\n");
        break;
    case 0x65:
        DES_PRINT("\tSTATUS:Error in SME\n");
        break;
    case 0x66 ... 0x6F:
        DES_PRINT("\tSTATUS:Reserved(0x%X)\n", pdu[0] & 0x7F);
        break;
    case 0x70 ... 0x7F:
        DES_PRINT("\tSTATUS:Values specific to each SC(0x%X)\n", pdu[0] & 0x7F);
        break;
    default:
        DES_PRINT("\tSTATUS:Unknown(0x%X)\n", pdu[0] & 0x7F);
        break;
    }

    return 1;
}

static int des_udl(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms->ud_len = pdu[0];

    DES_PRINT("\tUSER DATA LENGTH:%d\n", sms->ud_len);
    return 1;
}

static int des_mn(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tMESSAGE NUMBER:%d\n", pdu[0]);
    return 1;
}

static int des_ct(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int cmd_type = pdu[0];

    switch(cmd_type)  {
    case 0x00:
        DES_PRINT("\tCOMMAND TYPE:Enquiry relating to previously submitted SMS\n");
        break;
    case 0x01:
        DES_PRINT("\tCOMMAND TYPE:Cancel SRR relating to previously submitted SMS\n");
        break;
    case 0x02:
        DES_PRINT("\tCOMMAND TYPE:Delete previously submitted SMS\n");
        break;
    case 0x03:
        DES_PRINT("\tCOMMAND TYPE:Enable SRR relating to previously submitted SMS\n");
        break;
    case 0x04 ... 0x1F:
        DES_PRINT("\tCOMMAND TYPE:Reserved(0x%X)\n", cmd_type);
        break;
    case 0xE0 ... 0xFF:
        DES_PRINT("\tCOMMAND TYPE:Values specific for each SC(0x%X)\n", cmd_type);
        break;
    }
    return 1;
}

static int des_cdl(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms->cdl = pdu[0];

    DES_PRINT("\tCOMMAND DATA LENGTH:%d\n", sms->cdl);
    return 1;
}

static int des_cd(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    if(! sms->cdl)
        return 0;

    if(sms->cdl > len)  {
        DES_PRINT("\t<Invalid Command Data>\n");
        return -1;
    }

    /* TODO: command data parsing */
    HEX_DUMP(pdu, sms->cdl);
}

static int des_fcs(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int fcs = pdu[0];

    switch(fcs)  {
    case 0x80 ... 0x8F:
        DES_PRINT("\t<TP-PID errors>\n");
        break;
    case 0x90 ... 0x9F:
        DES_PRINT("\t<TP-DCS errors>\n");
        break;
    case 0xA0 ... 0xAF:
        DES_PRINT("\t<TP-Command Errors>\n");
        break;
    default:
    break;
    }

    switch(fcs)  {
    case 0x00 ... 0x7F:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0x80:
        DES_PRINT("\tFAILURE CAUSE:Telematic interworking not supported\n");
        break;
    case 0x81:
        DES_PRINT("\tFAILURE CAUSE:Short message Type 0 not supported\n");
        break;
    case 0x82:
        DES_PRINT("\tFAILURE CAUSE:Cannot replace short message\n");
        break;
    case 0x83 ... 0x8E:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0x8F:
        DES_PRINT("\tFAILURE CAUSE:Unspecified TP-PID error\n");
        break;
    case 0x90:
        DES_PRINT("\tFAILURE CAUSE:    Data coding scheme (alphabet) not supported\n");
        break;
    case 0x91:
        DES_PRINT("\tFAILURE CAUSE:Message class not supported\n");
        break;
    case 0x92 ... 0x9E:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0x9F:
        DES_PRINT("\tFAILURE CAUSE:Unspecified TP-DCS error\n");
        break;
    case 0xA0:
        DES_PRINT("\tFAILURE CAUSE:Command cannot be actioned\n");
        break;
    case 0xA1:
        DES_PRINT("\tFAILURE CAUSE:Command unsupported\n");
        break;
    case 0xA2 ... 0xAE:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0xAF:
        DES_PRINT("\tFAILURE CAUSE:Unspecified TP-Command error\n");
        break;
    case 0xB0:
        DES_PRINT("\tFAILURE CAUSE:TPDU not supported\n");
        break;
    case 0xB1 ... 0xBF:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0xC0:
        DES_PRINT("\tFAILURE CAUSE:SC busy\n");
        break;
    case 0xC1:
        DES_PRINT("\tFAILURE CAUSE:No SC subscription\n");
        break;
    case 0xC2:
        DES_PRINT("\tFAILURE CAUSE:SC system failure\n");
        break;
    case 0xC3:
        DES_PRINT("\tFAILURE CAUSE:Invalid SME address\n");
        break;
    case 0xC4:
        DES_PRINT("\tFAILURE CAUSE:Destination SME barred\n");
        break;
    case 0xC5:
        DES_PRINT("\tFAILURE CAUSE:SM Rejected-Duplicate SM\n");
        break;
    case 0xC6:
        DES_PRINT("\tFAILURE CAUSE:TP-VPF not supported\n");
        break;
    case 0xC7:
        DES_PRINT("\tFAILURE CAUSE:TP-VP not supported\n");
        break;
    case 0xC8 ... 0xCF:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0xD0:
        DES_PRINT("\tFAILURE CAUSE:SIM SMS storage full\n");
        break;
    case 0xD1:
        DES_PRINT("\tFAILURE CAUSE:No SMS storage capability in SIM\n");
        break;
    case 0xD2:
        DES_PRINT("\tFAILURE CAUSE:Error in MS\n");
        break;
    case 0xD3:
        DES_PRINT("\tFAILURE CAUSE:Memory Capacity Exceeded\n");
        break;
    case 0xD4:
        DES_PRINT("\tFAILURE CAUSE:SIM Application Toolkit Busy\n");
        break;
    case 0xD5 ... 0xDF:
        DES_PRINT("\tFAILURE CAUSE:Reserved(0x%X)\n", fcs);
        break;
    case 0xE0 ... 0xFE:
        DES_PRINT("\tFAILURE CAUSE:Values specific to an application\n");
        break;
    case 0xFF:
        DES_PRINT("\tFAILURE CAUSE:Unspecified error cause\n");
        break;
    }
    return 1;
}

static int des_udhi(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms->udhi = !! (pdu[0] & 0x40);
    return 0;
}


static int des_ud_hd(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int udhl = pdu[0], res, i, iei, iei_tag, iei_len, iei_res;

    if(udhl + 1 > len && udhl < 2)  {
        DES_IEI_PRINT("[ERR]Invalid user data header length\n");
        return -1;
    }

    DES_PRINT("\tUSER DATA HEADERS:\n");
    for(i = 0, pdu++; i < udhl;)  {
        iei_tag = pdu[i++] & 0xFF;
        iei_len = pdu[i++] & 0xFF;

        if(i + iei_len > udhl)  {
            DES_IEI_PRINT("[ERR]Invalid IEI data length\n");
            break;
        }

        switch(iei_tag)  {
        case 0x00:
            iei = IEI_CONCAT;
            break;
        case 0x01:
            iei = IEI_SPECIAL;
            break;
        case 0x02:
            iei = IEI_RESERVED;
            break;
        case 0x03:
            iei = IEI_NOT_USED;
            break;
        case 0x04:
            iei = IEI_PORT_8BIT;
            break;
        case 0x05:
            iei = IEI_PORT_16BIT;
            break;
        case 0x06:
            iei = IEI_SMSC_CTL;
            break;
        case 0x07:
            iei = IEI_UDH_SRC_IND;
            break;
        case 0x08:
            iei = IEI_CONCAT_16BIT;
            break;
        case 0x09:
            iei = IEI_WIRELESS_CTL;
            break;
        case 0x0A:
            iei = IEI_TEXT_FORMAT;
            break;
        case 0x0B:
            iei = IEI_PREDEFINED_SOUND;
            break;
        case 0x0C:
            iei = IEI_USER_DEFINED_SOUND;
            break;
        case 0x0D:
            iei = IEI_PREDEFINED_ANI;
            break;
        case 0x0E:
            iei = IEI_LARGE_ANI;
            break;
        case 0x0F:
            iei = IEI_SMALL_ANI;
            break;
        case 0x10:
            iei = IEI_LARGE_PIC;
            break;
        case 0x11:
            iei = IEI_SMALL_PIC;
            break;
        case 0x12:
            iei = IEI_VAR_PIC;
            break;
        case 0x13:
            iei = IEI_USER_PROMPT_IND;
            break;
        case 0x14:
            iei = IEI_EXT_OBJ;
            break;
        case 0x15:
            iei = IEI_REUSED_EXT_OBJ;
            break;
        case 0x16:
            iei = IEI_COMP_CTL;
            break;
        case 0x17:
            iei = IEI_OBJ_DIST_IND;
            break;
        case 0x18:
            iei = IEI_STANDARD_WVG_OBJ;
            break;
        case 0x19:
            iei = IEI_CHAR_SIZE_WVG_OBJ;
            break;
        case 0x1A:
            iei = IEI_EXT_OBJ_DATA_REQ_CMD;
            break;
        case 0x1B ... 0x1F:
            iei = IEI_RESERVED_FOR_EMS;
            break;
        case 0x20:
            iei = IEI_EMAIL_HEADER;
            break;
        case 0x21:
            iei = IEI_HYPERLINK_FORMAT;
            break;
        case 0x22:
            iei = IEI_REPLY_ADDR;
            break;
        case 0x23:
            iei = IEI_ENHANCED_VOICE_MAIL;
            break;
        case 0x24:
            iei = IEI_NATIONAL_LANG_SINGLE_SHIFT;
            break;
        case 0x25:
            iei = IEI_NATIONAL_LANG_LOCKING_SHIFT;
            break;
        case 0x26 ... 0x6F:
            iei = IEI_RESERVED;
            break;
        case 0x70 ... 0x7F:
            iei = IEI_USIM_TOOLKIT_SEC_HEADERS;
            break;
        case 0xA0 ... 0xBF:
        case 0xE0 ... 0xFF:
            iei = IEI_RESERVED_FOR_FUTURE;
            break;
        case 0x80 ... 0x9F:
            iei = IEI_SME_TO_SME_SPECIFIC;
            break;
        case 0xC0 ... 0xDF:
            iei = IEI_SC_SPECIFIC;
            break;
        default:
            iei = IEI_RESERVED;
            break;
        }

        DES_IEI_PRINT("\tINFO ELEMENT ID  :%s\n", iei_name[iei]);
        iei_res = iei_dess_tbl[iei](sms, cfg, pdu + i, iei_len);
        i += iei_len;
    }

    return udhl + 1;
}

static int des_ud(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    int res = 0, i;
    char *txt;

    if(sms->udhi)
        res = des_ud_hd(sms, cfg, desc, pdu, len);

    if((sms->ud_coding == CODING_GSM7BIT && len < (sms->ud_len * 7 / 8))
       || (sms->ud_coding != CODING_GSM7BIT && len < sms->ud_len))  {
        DES_PRINT("[ERR]Invalid user data length\n");
        return -1;
    }

    if(sms->compressed)  {
        DES_PRINT("\t<FIXME:Compressed User Data Not Supported Yet>\n");
        DES_PRINT("\tUSER DATA:\n");
        hex_dump(pdu + res, sms->ud_len - res, cfg->tp_cfg[desc->id]);
        return sms->ud_len;
    }

    for(i = 0; i < ARRAYSIZE(pre_dess_ud_tbl); i++)  {
        if(pre_dess_ud_tbl[i](sms, cfg, pdu + res, len - res))
            return sms->ud_len;
    }

    switch(sms->ud_coding)  {
    case CODING_GSM7BIT:
        DBG_PRINT("CODING_GSM7BIT UD len:%d\n", sms->ud_len);
        txt = decode_gsm7bit_packed(pdu + res,
                                    sms->ud_len - (res * 8 + 6) / 7, /* septets substract potential header */
                                    (7 - (res * 8) % 7) % 7); /* padding bits to septets boundary */
        res = (sms->ud_len * 7 + 7) / 8;
        break;
    case CODING_GSM8BIT:
        DBG_PRINT("CODING_GSM8BIT UD len:%d\n", sms->ud_len);
        txt = decode_gsm8bit_unpacked(pdu + res, sms->ud_len - res);
        res = sms->ud_len;
        break;
    case CODING_UCS2:
        DBG_PRINT("CODING_UCS2 UD len:%d\n", sms->ud_len);
        txt = decode_ucs16be(pdu + res, sms->ud_len - res);
        res = sms->ud_len;
        break;
    default:
        txt =  NULL;
        res = sms->ud_len;
        break;
    }

    if(txt)  {
        DES_PRINT("\tUSER DATA:%s\n", txt);
    }else  {
        DES_PRINT("\tUSER DATA:\n");
        if(sms->ud_coding == CODING_GSM7BIT)
            hex_dump(pdu + res, (sms->ud_len * 7 + 7) / 8 - res, cfg->tp_cfg[desc->id]);
        else
            hex_dump(pdu + res, sms->ud_len - res, cfg->tp_cfg[desc->id]);
    }

    if(sms->ud)
        free(sms->ud);
    sms->ud = txt;

    for(i = 0; i < ARRAYSIZE(pst_dess_ud_tbl); i++)  {
        if(pst_dess_ud_tbl[i](sms, cfg, txt))
            break;
    }

    return  res;
}

static int des_pi(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms->pid = !! (pdu[0] & 0x01);
    sms->dcs = !! (pdu[0] & 0x02);
    sms->udl = !! (pdu[0] & 0x04);

    DES_PRINT("\tPROTOCOL IDENTIFIER PRESENT:%s\n", sms->pid ? "YES" : "NO");
    DES_PRINT("\tDATA CODING SCHEME PRESENT:%s\n", sms->dcs ? "YES" : "NO");
    DES_PRINT("\tUSER DATA LENGTH PRESENT:%s\n", sms->udl ? "YES" : "NO");
    return 1;
}


static int des_smsc(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int l = pdu[0];
    char *addr;

    if(l > 0)  {
        if(l > len)  {
            printf("Invalid SMSC address len, too long!\n");
            return -1;
        }
        if(l <= 2)  {
            DES_PRINT("\tADDRESS:\"\"\n");
            return l + 1;
        }
        addr = decode_bcd_num(pdu + 2, (l - 1) * 2);
        DES_PRINT("\tADDRESS:%s\n", addr ? : "<Null of Fail to Decode>");
        if(addr)
            free(addr);
    }

    return l + 1;
}


static inline int __des_iei_default(des_ctx *cfg, unsigned char *pdu, size_t len)
{
    if(len > 0)
        __hex_dump(2, pdu, len, cfg->tp_cfg[TP_UD_HD]);
    return len;
}

static int des_iei_reserved(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_not_used(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_concat(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
  unsigned int ref, cnt, seq;

    if(len != 3)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of Concat Message>\n");
        return len;
    }

    sms->ref = ref = pdu[0];
    sms->cnt = cnt = pdu[1];
    sms->seq = seq = pdu[2];
    DES_IEI_PRINT("\t\tMESSAGE REFERENCE:%d\n", ref);
    DES_IEI_PRINT("\t\tMESSAGE COUNT:%d\n", cnt);
    DES_IEI_PRINT("\t\tMESSAGE SEQUENCE:%d\n", seq);
    return len;
}


static int des_iei_special(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    if(len != 2)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of Special Message Indication>\n");
        return len;
    }

    DES_IEI_PRINT("\t\tINDICATION MESSAGE STORAGE:%s\n", (pdu[0] & 0x80) ? "Store" : "Discard");
    switch(pdu[0] & 0x7F)  {
    case 0:
        DES_IEI_PRINT("\t\tINDICATION TYPE:Voice Message Waiting\n");
        break;
    case 1:
        DES_IEI_PRINT("\t\tINDICATION TYPE:Fax Message Waiting\n");
        break;
    case 2:
        DES_IEI_PRINT("\t\tINDICATION TYPE:Electronic Mail Message Waiting\n");
        break;
    case 3:
        DES_IEI_PRINT("\t\tINDICATION TYPE:Other Message Waiting(Ref. GSM 03.38)\n");
        break;
    default:
        DES_IEI_PRINT("\t\tINDICATION TYPE:Unknown\n");
        break;
    }
    DES_IEI_PRINT("\t\tINDICATION MESSAGE COUNT:%d%s\n", pdu[1], (pdu[1] != 255) ? "" : " or greater");
    return len;
}


static int des_iei_port_8bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    if(len != 2)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of Application Port(8bit)>\n");
        return len;
    }

    sms->dst_8 = pdu[0];
    sms->src_8 = pdu[1];
    DES_IEI_PRINT("\t\tDESTINATION PORT:%d\n", pdu[0]);
    DES_IEI_PRINT("\t\tORIGINATOR PORT:%d\n", pdu[1]);
    return len;
}


static int des_iei_port_16bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    unsigned int i;

    if(len != 4)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of Application Port(16bit)>\n");
        return len;
    }

    i = pdu[0];
    sms->dst_16 = (i << 8) | pdu[1];
    i = pdu[2];
    sms->src_16 = (i << 8) | pdu[3];
    DES_IEI_PRINT("\t\tDESTINATION PORT:%d\n", sms->dst_16);
    DES_IEI_PRINT("\t\tORIGINATOR PORT:%d\n", sms->src_16);
    return len;
}


static int des_iei_smsc_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    if(len != 1)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of SMSC Control Parameter>\n");
        return len;
    }

    DES_IEI_PRINT("\t\tStatus Report For SMS Transaction Completed: %s\n", (pdu[0] & 0x01) ? "YES" : "NO");
    DES_IEI_PRINT("\t\tNo more transfer attempts:\n");
    DES_IEI_PRINT("\t\tStatus Report For Permanet Error:%s\n", (pdu[0] & 0x02) ? "YES" : "NO");
    DES_IEI_PRINT("\t\tStatus Report For Temporary Error:%s\n", (pdu[0] & 0x04) ? "YES" : "NO");
    DES_IEI_PRINT("\t\tStill trying to transfer:\n");
    DES_IEI_PRINT("\t\tStatus Report For Temporary Error:%s\n", (pdu[0] & 0x08) ? "YES" : "NO");
    DES_IEI_PRINT("\t\tError Cancels SRR Of The Rest In Concatenated:%s\n", (pdu[0] & 0x40) ? "YES" : "NO");
    DES_IEI_PRINT("\t\tInclude Original UDH Into Status Report:%s\n", (pdu[0] & 0x80) ? "YES" : "NO");
    return len;
}


static int des_iei_udh_src_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    if(len != 1)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of SMSC Control Parameter>\n");
        return len;
    }

    switch(pdu[0])  {
    case 0:
        if(sms->mti & MTI_STATUS_REPORT)
            DES_IEI_PRINT("\t\tUSER DATA HEADERS CREATED BY ORIGINAL SENDER:\n");
        else
            DES_IEI_PRINT("\t\t<Invalid UDH Source Indicator(0x%X)>\n", pdu[0]);
        break;
    case 1:
        if(sms->mti & MTI_STATUS_REPORT)
            DES_IEI_PRINT("\t\tUSER DATA HEADERS CREATED BY ORIGINAL RECEIVER:\n");
        else
            DES_IEI_PRINT("\t\t<Invalid UDH Source Indicator(0x%X)>\n", pdu[0]);
        break;
    case 2:
        DES_IEI_PRINT("\t\tUSER DATA HEADERS CREATED BY THE SMSC:\n");
        break;
    default:
        DES_IEI_PRINT("\t\t<Invalid UDH Source Indicator(0x%X)>\n", pdu[0]);
    }
    return len;
}


static int des_iei_concat_16bit(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
  unsigned int ref, cnt, seq;

    if(len != 4)  {
        DES_IEI_PRINT("\t\t<Invalid IEI of Concat Message 16bit>\n");
        return len;
    }

    ref = pdu[0];
    sms->ref_16 = ref = ((ref << 8) & pdu[1]);
    sms->cnt_16 = cnt = pdu[2];
    sms->seq_16 = seq = pdu[3];
    DES_IEI_PRINT("\t\tMESSAGE REFERENCE:%d\n", ref);
    DES_IEI_PRINT("\t\tMESSAGE COUNT:%d\n", cnt);
    DES_IEI_PRINT("\t\tMESSAGE SEQUENCE:%d\n", seq);
    return len;
}


/* ref. Wireless Control Message Protocol (WCMP)  */
static int des_iei_wireless_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


/* TODO: more detailed dessecting */
static int des_iei_text_format(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_predefined_sound(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_user_defined_sound(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_predefined_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_large_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_small_ani(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_large_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_small_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_var_pic(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_user_prompt_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_ext_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_reused_ext_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_comp_ctl(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_obj_dist_ind(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_standard_wvg_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_char_size_wvg_obj(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_ext_obj_data_req_cmd(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_reserved_for_ems(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_email_header(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_hyperlink_format(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_reply_addr(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_enhanced_voice_mail(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_national_lang_single_shift(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_national_lang_locking_shift(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_usim_toolkit_sec_headers(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_reserved_for_future(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_sme_to_sme_specific(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


static int des_iei_sc_specific(sms *sms, des_ctx *cfg, unsigned char *pdu, size_t len)
{
    return __des_iei_default(cfg, pdu, len);
}


/* CDMA */
static sms_addr *___des_pid_addr(unsigned char *pdu, size_t len)
{
    sms_addr addr, *paddr;
    unsigned int length, charoffset, shift, bitoffset = 2;

    addr.d_mode = !! (pdu[0] & 0x80);
    addr.n_mode = !!(pdu[0] & 0x40);
    addr.ton_avail = addr.d_mode;
    addr.npi_avail = (addr.d_mode && ! addr.n_mode);
    if(addr.ton_avail)  {
        addr.ton_val = (pdu[0] >> 3) & 0x07;
        bitoffset += 3;
        if(addr.n_mode)  {
            switch(addr.ton_val)  {
            case 1:
                addr.ton = TON_INTERNATIONAL;
                break;
            case 2:
                addr.ton = TON_NATIONAL;
                break;
            case 3:
                addr.ton = TON_NETWORK_SPECIFIC;
                break;
            case 4:
                addr.ton = TON_SUBSCRIBER;
                break;
            case 6:
                addr.ton = TON_ABBREVIATED;
                break;
            default:
                addr.ton = TON_RESERVED;
                break;
            }
        }else  {
            switch(addr.ton_val)  {
            case 1:
                addr.ton = TON_IP;
                break;
            case 2:
                addr.ton = TON_IEA;
                break;
            default:
                addr.ton = TON_UNKNOWN;
                break;
            }
        }
    }
    if(addr.npi_avail)  {
        addr.npi_val = pdu[0] & 0x03;
        addr.npi_val = ((addr.npi_val << 1) | ((pdu[1] >> 7) & 0x01));
        bitoffset += 4;
        switch(addr.npi_val)  {
        case 0:
            addr.npi = NPI_UNKNOWN;
            break;
        case 1:
            addr.npi = NPI_ISDN_TELEPHONE;
            break;
        case 3:
            addr.npi = NPI_DATA;
            break;
        case 4:
            addr.npi = NPI_TELEX;
            break;
        case 5:
            addr.npi = NPI_PRIVATE;
            break;
        default:
            addr.npi = NPI_RESERVED;
            break;
        }
    }

    charoffset = bitoffset / 8;
    shift = bitoffset % 8;
    length = (pdu[charoffset] & ((1 << (8 - shift)) - 1));
    if(shift > 0)
        length = ((length << shift) | ((pdu[charoffset + 1] >> (8 - shift)) & ((1 << shift) - 1)));

    bitoffset += 8;
    if(! addr.d_mode)  {
        addr.addr = decode_bcd_num_cdma(pdu, length, bitoffset);
    }else if(addr.n_mode)  {
        if(addr.ton == TON_IEA)  {
            addr.addr = decode_asc7bit_unpacked(pdu, length, bitoffset);
        }else if(addr.ton == TON_IP)  {
            addr.addr = decode_ip_addr(pdu, bitoffset);
        }else  {
            addr.addr = strdup("<No support to decode>");
        }
    }else  {
        addr.addr = decode_asc7bit_unpacked(pdu, length, bitoffset);
    }

    paddr = memdup(&addr, sizeof(addr));
    if(! paddr)
        free(addr.addr);
    return paddr;
}


static sms_addr *__des_pid_addr(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms_addr *addr = ___des_pid_addr(pdu, len);

    if(addr)  {
        DES_PRINT("\tDIGIT  MODE:%s\n", addr->d_mode ? "YES" : "NO");
        DES_PRINT("\tNUMBER MODE:%s\n", addr->n_mode ? "YES" : "NO");
        if(addr->ton_avail)
            DES_PRINT("\tNUMBER TYPE:%s\n", ton_tbl[addr->ton]);
        if(addr->npi_avail)
            DES_PRINT("\tNUMBER PLAN:%s\n", npi_tbl[addr->npi]);
        DES_PRINT("\tNUMBER ADDR:%s\n", addr->addr ? : "<Empty or fail to decode>");
    }
    return addr;
}


static inline int __des_default(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    if(len > 0)
        __hex_dump(1, pdu, len, cfg->tp_cfg[desc->id]);
    return len;
}


static int des_pid_TSID(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int id = pdu[0];
    const char *ts = "Unknown";

    id = (id << 8) |  pdu[1];
    switch(id)  {
    case 0x1002:
        ts = "Wireless Messaging Teleservice(WMT)";
        break;
    case 0x1003:
        ts = "Voice Mail Notification(VMN)";
        break;
    case 0x1004:
        ts = "Wireless Application Protocol(WAP)";
        break;
    case 0x1005:
        ts = "Wireless Enhanced Messaging Teleservice(WEMT)";
        break;
    default:
        break;
    }

    DES_PRINT("\tSERVICE:%s\n", ts);
    return 2;
}


static const char *service_categories[] = {
    "Unknown or unspecified",
    "Emergency Broadcasts",
    "Administrative",
    "Maintenance",
    "General News – Local",
    "General News – Regional",
    "General News – National",
    "General News – International",
    "Business/Financial News – Local",
    "Business/Financial News – Regional",
    "Business/Financial News – National",
    "Business/Financial News – International",
    "Sports News – Local",
    "Sports News – Regional",
    "Sports News – National",
    "Sports News – International",
    "Entertainment News – Local",
    "Entertainment News – Regional",
    "Entertainment News – National",
    "Entertainment News – International",
    "Local Weather",
    "Area Traffic Reports",
    "Local Airport Flight Schedules",
    "Restaurants",
    "Lodgings",
    "Retail Directory",
    "Advertisements",
    "Stock Quotes",
    "Employment Opportunities",
    "Medical/Health/Hospitals",
    "Technology News",
    "Multi-category",
    "Card Application Toolkit Protocol Teleservice (CATPT)",
};

static int des_pid_SC(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int id = pdu[0];
    const char *sc = "Reserved";

    id = (id << 8) |  pdu[1];
    if(id < ARRAYSIZE(service_categories))
        sc = service_categories[id];
    DES_PRINT("\tCATEGORY:%s\n", sc);
    return 2;
}


static int des_pid_OA(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms_addr *addr =  __des_pid_addr(sms, cfg, desc, pdu, len);

    if(sms->oa)
        free_addr(sms->oa);
    sms->oa = addr;
    return len;
}


static int des_pid_OSA(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static int des_pid_DA(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    sms_addr *addr =  __des_pid_addr(sms, cfg, desc, pdu, len);

    if(sms->da)
        free_addr(sms->da);
    sms->da = addr;
    return len;
}


static int des_pid_DSA(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static int des_pid_BRO(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int seq = ((pdu[0] >> 2) & 0x3F);

    DES_PRINT("\tSEQENCE:%d\n", seq);
    return 1;
}


static const char *sms_fail_cause(unsigned int code)
{
    switch(code)  {
    case 0: return "Address vacant";
    case 1: return "Address translation failure";
    case 2: return "Network resource shortage";
    case 3: return "Network failure";
    case 4: return "Invalid Teleservice ID";
    case 5 ... 31: return "Other network problem";
    case 32: return "No page response";
    case 33: return "Destination busy";
    case 34: return "No acknowledgment";
    case 35: return "Destination resource shortage";
    case 36:
    case 48 ... 63: return "SMS delivery postponed";
    case 37: return "Destination out of service";
    case 38: return "Destination no longer at this address";
    case 39 ... 47: return "Other terminal problem";
    case 64: return "Radio interface resource shortage";
    case 65: return "Radio interface incompatibility";
    case 66 ... 95: return "Other radio interface problem";
    default:
        break;
    }
    return "Unknown";
}

static int des_pid_CC(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int seq = ((pdu[0] >> 2) & 0x3F);
    unsigned int cls = pdu[0] & 0x03;
    const char *ec = "No error";

    switch(cls)  {
    case 0x02:
        ec = "Temporary error";
        break;
    case 0x03:
        ec = "Permanent error";
        break;
    default:
        ec = "Unknown error";
        break;
    }

    DES_PRINT("\tSEQENCE:%d\n", seq);
    DES_PRINT("\tCLASS  :%s\n", ec);
    if(cls != 0 && len == 2)
        DES_PRINT("\tCAUSE  :%s\n", sms_fail_cause(pdu[1]));
    return len;
}


static int des_spid_MID(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int type = ((pdu[0] >> 4) & 0x0F);
    unsigned int id, hdi;
    const char *type_name = "Reserved";

    switch(type)  {
    case 0x01:
        type_name = "Deliver(mobile-terminated only)";
        break;
    case 0x02:
        type_name = "Submit(mobile-originated only)";
        break;
    case 0x03:
        type_name = "Cancellation(mobile-originated only)";
        break;
    case 0x04:
        type_name = "Delivery Acknowledgment(mobile-terminated only)";
        break;
    case 0x05:
        type_name = "User Acknowledgment(either direction)";
        break;
    case 0x06:
        type_name = "Read Acknowledgment(either direction)";
        break;
    default:
        break;
    }

    id = pdu[0] & 0x0F;
    id = ((id << 8) | pdu[1]);
    id = ((id << 4) | (pdu[2] >> 4));

    hdi = !! (pdu[2] & 0x08);
    sms->udhi = hdi;

    DES_PRINT("\tMESSAGE TYPE  :%s\n", type_name);
    DES_PRINT("\tMESSAGE ID    :%d\n", id);
    DES_PRINT("\tMESSAGE HEADER:%s\n", hdi ? "Present" : "Not present");
    return 3;
}


static const struct coding_tbl{
    char *name;
    int coding;
}coding_tbl[] = {
    {"Octet, unspecified", CODING_OCTET},
    {"IS-91 Extended Protocol Message", CODING_IS91},
    {"7-bit ASCII(ANSI X3.4)", CODING_ASC7BIT},
    {"IA5(Table 11 of ITU-T T.50)", CODING_IA5},
    {"UNICODE(ISO/IEC 10646-1:1993)", CODING_UNICODE},
    {"Shift-JIS", CODING_SHIFTJIS},
    {"Korean(KS X 1001:1998)", CODING_KOREAN},
    {"Latin/Hebrew (ISO 8859-8:1988)", CODING_LATIN_HEBREW},
    {"Latin(ISO 8859-1:1988)", CODING_LATIN},
};

static int des_spid_UD(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int idx, coding, msg_type, length, bitoffset = 5;
    const char *coding_name;
    char *txt = NULL;

    idx = (pdu[0] >> 3) & 0x1F;
    coding = (idx < ARRAYSIZE(coding_tbl)) ? coding_tbl[idx].coding : CODING_UNKNOWN;
    coding_name = (idx < ARRAYSIZE(coding_tbl)) ? coding_tbl[idx].name : "Reserved";

    sms->ud_coding = coding;
    DES_PRINT("\tENCODING :%s(%d)\n", coding_name, coding);
    if(coding == 0x01)  {
        msg_type = pdu[0] & 0x07;
        msg_type = ((msg_type << 5) | (pdu[1] >> 3));
        /* ref. Table 9 of TIA/EIA/IS-91 */
        DES_PRINT("\tTYPE     :%d\n", msg_type);
        bitoffset += 8;
    }

    length = pdu[bitoffset / 8] & 0x07;
    length = ((length << 5) | (pdu[bitoffset / 8 + 1] >> 3));
    sms->ud_len = length;
    bitoffset += 8;

    DES_PRINT("\tLENGTH   :%d\n", length);
    /* TODO: more decode method supported */
    switch(coding)  {
    case CODING_ASC7BIT:
        txt = decode_asc7bit_packed(pdu, length, bitoffset);
        break;
    case CODING_UNICODE:
        txt = decode_unicode(pdu, length, bitoffset);
        break;
    default:
        txt = NULL;
        break;
    }

    if(sms->ud)
        free(sms->ud);
    sms->ud = txt;

    if(txt)  {
        DES_PRINT("\tUSER DATA:%s\n", txt);
    }else  {
        DES_PRINT("\tUSER DATA:<Not supported decoding>\n");
        HEX_DUMP(pdu, len);
    }

    return len;
}


static int des_spid_URC(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tCODE:%d\n", pdu[0]);
    return 1;
}


static int __des_spid_ts(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu)
{
    int year, mon, day, hour, min, sec;

    year = decode_bcd_cdma(pdu[0]);
    mon = decode_bcd_cdma(pdu[1]) - 1;
    day = decode_bcd_cdma(pdu[2]);
    hour = decode_bcd_cdma(pdu[3]);
    min = decode_bcd_cdma(pdu[4]);
    sec = decode_bcd_cdma(pdu[5]);

    if(year < 96)
        year += 2000;
    else
        year += 1900;

    DES_PRINT("\tTIME STAMP:%s%d %d %2d:%2d:%2d\n",
              (mon < ARRAYSIZE(mon_tbl)) ? mon_tbl[mon] : "<Invalid month>",
              day, year, hour, min, sec);

    return 6;
}


static int __des_spid_ts_r(des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu)
{
    switch(pdu[0])  {
    case 245:
        DES_PRINT("\tVALID THROUGH:Indefinite\n");
        break;
    case 246:
        DES_PRINT("\tVALID THROUGH:Immediate\b");
        break;
    case 247:
        DES_PRINT("\tVALID THROUGH:Valid until mobile becomes inactive\n"
                  "\t              Deliver when mobile next becomes active\n");
        break;
    case 248:
        DES_PRINT("\tVALID THROUGH:Valid until registration area changes\n"
                  "\t              Discard if not registered\n");
        break;
    case 249 ... 255:
        DES_PRINT("\tVALID THROUGH:<Reserved value %d>", pdu[0]);
        break;
    default:
        __des_vp_relative(cfg, desc, pdu);
        break;
    }
    return 1;
}

static int des_spid_MCTS(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    return __des_spid_ts(cfg, desc, pdu);
}


static int des_spid_VP_A(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    return __des_spid_ts(cfg, desc, pdu);
}


static int des_spid_VP_R(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    return __des_spid_ts_r(cfg, desc, pdu);
}


static int des_spid_DDT_A(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    return __des_spid_ts(cfg, desc, pdu);
}


static int des_spid_DDT_R(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    return __des_spid_ts_r(cfg, desc, pdu);
}

static const char *pri_tbl[] = {
    "Normal",
    "Interactive",
    "Urgent",
    "Emergency",
};

static int des_spid_PI(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tPRIORITY:%s\n", pri_tbl[(pdu[0] >> 6) & 0x03]);
    return 1;
}


static const char *privacy_tbl[] = {
    "Not restricted(privacy level 0)",
    "Restricted(privacy level 1)",
    "Confidential(privacy level 2)",
    "Secret(privacy level 3)",
};


static int des_spid_PRI(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tPRIVACY:%s\n", privacy_tbl[(pdu[0] >> 6) & 0x03]);
    return 1;
}


static int des_spid_RO(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tPOSITIVE ACKNOWLEDGEMENT:%s\n", (pdu[0] & 0x80) ? "Requested" : "Not requested");
    DES_PRINT("\tDELIVERY ACKNOWLEDGEMENT:%s\n", (pdu[0] & 0x40) ? "Requested" : "Not requested");
    DES_PRINT("\tREAD     ACKNOWLEDGEMENT:%s\n", (pdu[0] & 0x20) ? "Requested" : "Not requested");
    return 1;
}


static int des_spid_NM(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    char msg_cnt[3];

    msg_cnt[0] = bcd_tbl[pdu[0] >> 4];
    msg_cnt[1] = bcd_tbl[pdu[0] & 0x0F];
    msg_cnt[2] = '\0';
    DES_PRINT("tCOUNT:%s\n", msg_cnt);
    return 1;
}


static const char *alert_tbl[] = {
    "Use Mobile default alert",
    "Use Low-priority alert",
    "Use Medium-priority alert",
    "Use High-priority alert",
};

static int des_spid_AMD(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tALERT:%s\n", alert_tbl[(pdu[0] >> 6) & 0x03]);
    return 1;
}


static const char *li_table[] = {
    "Unknown or unspecified",
    "English",
    "French",
    "Spanish",
    "Japanese",
    "Korean",
    "Chinese",
    "Hebrew",
};

static int des_spid_LI(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tLANGUAGE:%s\n", (pdu[0] < ARRAYSIZE(li_table)) ? li_table[pdu[0]] : "Reserved");
    return 1;
}


static int des_spid_CBN(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static const char *mdm_tbl[] = {
    "Immediate Display",
    "Mobile default settings",
    "User Invoke",
    "Reserved",
};


static int des_spid_MDM(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    DES_PRINT("\tMODE:%s\n", mdm_tbl[(pdu[0] >> 6) & 0x03]);
    return 1;
}


static int des_spid_MEUD(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static int des_spid_MDI(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int index = pdu[0];

    index = (index << 8) & pdu[1];
    DES_PRINT("\tINDEX:%d\n", index);
    return 2;
}


static int des_spid_SCPD(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static int des_spid_SCPR(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    /* TODO: */
    return __des_default(cfg, desc, pdu, len);
}


static const char *err_cls_tbl[] = {
    "No error",
    "Reserved",
    "Temporary",
    "Permanent",
};

static const char *status_tbl[] = {
    /* no error */
    "Message accepted",
    "Message deposited to Internet",
    "Message delivered",
    "Message cancelled",
    "Network congestion",
    "Network error",
    "Cancel failed",
    "Blocked destination",
    "Text too long",
    "Duplicate message",
    "Invalid destination",
    "Message expired",
};


static int des_spid_MS(sms *sms, des_ctx *cfg, const tpdu_parm *desc, unsigned char *pdu, size_t len)
{
    unsigned int cls, code;

    cls = (pdu[0] >> 6) & 0x03;
    code = pdu[0] & 0x3F;

    DES_PRINT("\tCLASS:%s\n", err_cls_tbl[cls]);
    DES_PRINT("\tCODE :%s\n", (code < ARRAYSIZE(status_tbl)) ? status_tbl[code] : "Unknown error");
    return 1;
}


static unsigned int cdma_mti_detect(sms *sms, int t)
{
    sms_info *info = find_sms_info(sms, SPID_MID);
    unsigned char type;

    if(info)  {
        type = sms->pdu[info->offset + sms->base];
        switch((type >> 4) & 0x0F)  {
        case 1:
            return SMS_CDMA_DELIVER;
        case 2:
            return SMS_CDMA_SUBMIT;
        case 3:
            return SMS_CDMA_CANCEL;
        case 4:
            return SMS_CDMA_DELIVER_ACK;
        case 5:
            return SMS_CDMA_USER_ACK;
        case 6:
            return SMS_CDMA_READ_ACK;
        default:
            break;
        }
    }

    return SMS_RESERVED;
}

static unsigned int mti_detect(unsigned char *pdu, int type)
{
    unsigned char mti = (pdu[0] & 0x03);

    switch(mti)  {
    case 0:
        if(type == SMS_DELIVER_REPORT_ERR || type == SMS_DELIVER_REPORT_ACK)
            return type;
        return SMS_DELIVER;
    case 1:
        if(type == SMS_SUBMIT_REPORT_ERR || type == SMS_SUBMIT_REPORT_ACK)
            return type;
        return SMS_SUBMIT;
    case 2:
        if(type == SMS_COMMAND)
            return SMS_COMMAND;
        return SMS_STATUS_REPORT;
    default:
        return SMS_RESERVED;
    }
}

static inline void dump_des_opt(void)
{
    int i;

    printf("Available TPDU fields:\n");
    for(i = 0; i < ARRAYSIZE(des_ctx_opt); i++)  {
        printf("%-12s  %s\n", des_ctx_opt[i].name, des_ctx_opt[i].desc);
    }
    printf("\n");
}


static inline void usage(const char *prg)
{
    printf("%s [OPTIONS] PDU1 PDU2 ...\n", prg);
    printf("OPTIONS:\n");
    printf("--cdma|-c           decode cdma message\n"
           "--full|-f           full dump[DEFAULT]\n"
           "--simple|-s         simple header and user data\n"
           "--help|-h           print this message\n"
           "--tpdu|-p NAME...   print TPDU field listed only\n"
           "--list|-l           list available TPDU fields\n"
           "--type|-t NAME      specify PDU type\n"
           "--no-smsc|-n        no smsc header before DELIVER(TS 27.005)\n"
           "--raw|-r            dump raw TPDU data possible\n"
           "--version|-v        print version\n"
           "GSM PDU types:\n"
           "\tDELIVER, DELIVER_REPORT_ERR, DELIVER_REPORT_ACK\n"
           "\tSTATUS_REPORT, COMMAND, SUBMIT, SUBMIT_REPORT_ERR\n"
           "\tSUBMIT_REPORT_ACK\n"
           "CDMA PDU types:\n"
           "\tDELIVER, SUBMIT, CANCEL, DELIVER_ACK, USER_ACK\n"
           "\tREAD_ACK\n"
           "if GSM SMS type not specified, will detect between\n"
           "DELIVER, STATUS_REPORT and SUBMIT, may NOT correct\n"
           "if otherwise\n");
}


static inline void version(void)
{
    printf("smspy version %s\n", SMSPY_VERSION);
    printf("NOTE:\n"
           "1. GSM 03.40 compliant, TS 23.040 not fully supported.\n"
           "2. GSM SMS Command data parsing not supported.\n"
           "3. GSM SMS user data decompression not supported.\n"
           "4. Only ASCII 7bit and UNICODE encoding supported for CDMA SMS\n");
}


static void des_ctx_cfg(des_ctx *cfg, const char *tp_list)
{
    char *tok, *str = strdup(tp_list);
    int i;

    /* overwrite the default */
    memset(cfg->tp_cfg, 0, sizeof(cfg->tp_cfg));
    if(str)   {
        for(tok = strtok(str, "'"); tok; tok = strtok(NULL, "'"))  {
            for(i = 0; i < ARRAYSIZE(des_ctx_opt); i++)  {
                if(strstr(tok, des_ctx_opt[i].name))  {
                    cfg->tp_cfg[i] = 1;
                    break;
                }
            }
        }
        free(str);
    }
}

static int sms_dessect_begin(sms *sms, const char *hex, int cdma, int smsc)
{
    int len;
    unsigned char *pdu;

    pdu = dehex_string(hex, &len);
    if(! pdu || ! len)  {
        printf("Invalid SMS PDU to dessect:%s\n", hex);
        return -1;
    }

#ifndef NDEBUG
    ___hex_dump(0, pdu, len);
#endif

    memset(sms, 0, sizeof(*sms));

    sms->cdma = cdma;
    sms->smsc = smsc;

    sms->hex = hex;
    sms->pdu = pdu;
    sms->len = len;
    return 0;
}


static inline __tpdu_parm_fixed(const tpdu_parm *parm)
{
    return (parm->offset >= 0
            && parm->len > 0
            && ((parm->shift >= 0 && parm->size > 0)
                || parm->shift < 0));
}

static int __dessect_basic(sms *sms)
{
    const tpdu_parm **parm;
    sms_info *info;

    for(parm = tpdu_parm_tbl; *parm; parm++)  {
        if(! *parm)
            break;
        if(__tpdu_parm_fixed(*parm) && ((*parm)->mti & sms->mti))  {
            info = new_sms_info(*parm);
            if(! info)
                return -1;
            insert_info(sms, info);
        }
    }

    return 0;
}

static int append_tpdu_parm(sms *sms, int id)
{
    sms_info *info;
    const tpdu_parm *parm;

    if(find_tpdu_desc(sms, id))
        return 0;

    parm = get_tpdu_desc(sms->mti, id);
    if(parm)  {
        info = new_sms_info(parm);
        if(info)  {
            append_info(sms, info);
            return 0;
        }
    }
    return -1;
}

static inline void assert_if_fail(int exp)
{
    assert(exp);
}


static int do_dessect(sms *sms)
{
    const tpdu_parm *parm;
    sms_info *info, *del;
#ifndef NDEBUG
    des_ctx cfg = {stdout, 1, {[0 ... NUM_TP - 1] = 1},};
#else
    des_ctx cfg = {.out = NULL};
#endif
    unsigned char *pdu = sms->pdu + sms->base;
    unsigned int len = sms->len - sms->base, offset, res;

    /* CDMA msg do not got here */
    assert(! sms->cdma);
    if(sms->smsc && sms->base > 0 && ! sms->smsc_info)  {
        parm = get_tpdu_desc(sms->mti, TP_SMSC);
        if(! parm)  {
            printf("Invalid PDU to dessect a SMSC!\n");
            return -1;
        }
        sms->smsc_info = new_sms_info(parm);
        if(sms->smsc_info)  {
            sms->smsc_info->offset = 0;
            sms->smsc_info->len = sms->base;
            sms->smsc_info->shift = -1;
        }
    }

    if(sms->smsc_info)  {
        res = sms->smsc_info->handler->des_func(sms, &cfg, sms->smsc_info->handler, sms->pdu, sms->base);
        if(res < 0)  {
            printf("Fail to dessect SMSC address!\n");
            return res;
        }else if(res > 0 && res != sms->base)  {
            printf("Expected %d bytes dessected for SMSC address!\n", sms->base);
            return -1;
        }
    }

    for(offset = 0, del = NULL, parm = NULL, info = sms->info;
        info; info = info->nxt)  {
        if(del)  {
            delete_info(sms, del);
            del = NULL;
        }

        parm = info->handler;
        if(sms->vpf == VPF_NONE && parm->id == TP_VP)  {
            del = info;
            continue;
        }

        if(sms->pi)  {
            if((! sms->pid && parm->id == TP_PID)
               || (! sms->dcs && parm->id == TP_DCS)
               || (! sms->udl && (parm->id == TP_UDL || parm->id == TP_UD)))  {
                del = info;
                continue;
            }
        }

        if(__tpdu_parm_fixed(parm))  {
            /* all fixed tpdu desc must lie before indeterministic descs */
            if(offset > parm->offset)  {
                printf("Bad offset while processing %s:%d,%d\n", 
                       tpdu_id_name[parm->id], offset, parm->offset);
                return -1;
            }

            offset = parm->offset;
            if(parm->des_func)  {
                DBG_PRINT("call des_func of %s:%d, %d\n",
                          tpdu_id_name[parm->id], offset, len - offset);

                res = parm->des_func(sms, &cfg, parm, pdu + offset, len - offset);
                if(res < 0)  {
                    printf("Bad return value %d for %s\n", res, tpdu_id_name[parm->id]);
                    return res;
                }
                if(res > 0 && res != parm->len)  {
                    printf("Bad return value %d for %s:expected = %d\n",
                           res, tpdu_id_name[parm->id], len);
                    return -1;
                }
            }

            /* skip bitset dessectors */
            if(parm->shift < 0)
                offset += parm->len;
        }else if(! parm->des_func)  {
            printf("NULL des func for %s\n", tpdu_id_name[parm->id]);
            return -1;
        }else  {
            if(parm->offset >= 0)  {
                assert(offset <= parm->offset);
                offset = parm->offset;
            }

            DBG_PRINT("call des_func of %s:%d, %d\n",
                      tpdu_id_name[parm->id], offset, len - offset);

            res = parm->des_func(sms, &cfg, parm, pdu + offset, len - offset);

            DBG_PRINT("des_fun of %s returned %d\n", tpdu_id_name[parm->id], res);
            if(res < 0)  {
                printf("Bad return value %d for %s\n", res, tpdu_id_name[parm->id]);
                return res;
            }

            if(res == 0 && parm->len < 0)  {
                printf("Bad return value %d for %s:expected > 0\n", res, tpdu_id_name[parm->id]);
                return -1;
            }

            if(parm->offset < 0)
                info->offset = offset;
            if(parm->len < 0)
                info->len = res;
            offset += res;
        }
    }

    if(del)
        delete_info(sms, del);

    return 0;
}


/*
 * MMS_DELIVER type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-MMS TP-SRI  |
 * |TP-UDHI TP-RP            |
 * +-------------------------+
 * |2 to 12. TP-OA           |
 * +-------------------------+
 * |1. TP-PID                |
 * +-------------------------+
 * |1. TP-DCS                |
 * +-------------------------+
 * |7. TP-SCTS               |
 * +-------------------------+
 * |1. TP-UDL                |
 * +-------------------------+
 * |0 to 140. TP-UD          |
 * +-------------------------+
 */
static int dessect_deliver(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    assert_if_fail(! append_tpdu_parm(sms, TP_OA));
    assert_if_fail(! append_tpdu_parm(sms, TP_PID));
    assert_if_fail(! append_tpdu_parm(sms, TP_DCS));
    assert_if_fail(! append_tpdu_parm(sms, TP_SCTS));
    assert_if_fail(! append_tpdu_parm(sms, TP_UDL));
    assert_if_fail(! append_tpdu_parm(sms, TP_UD));

    return do_dessect(sms);
}


/*
 * MMS_DELIVER_REPORT err type PDU format
 * +-------------------------+
 * |1. TP-MTI                |
 * +-------------------------+
 * |1. TP-FCS                |
 * +-------------------------+
 */
static int dessect_deliver_report_err(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));
    return do_dessect(sms);
}


/*
 * MMS_DELIVER_REPORT ack type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-UDH         |
 * +-------------------------+
 * |1. TP-PI                 |
 * +-------------------------+
 * |0,1. TP-PID              |
 * +-------------------------+
 * |0,1. TP-DCS              |
 * +-------------------------+
 * |0,1. TP-UDL              |
 * +-------------------------+
 * |0 to 159. TP-UD          |
 * +-------------------------+
 */
static int dessect_deliver_report_ack(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    sms->pi = 1;
    assert_if_fail(! append_tpdu_parm(sms, TP_PID));
    assert_if_fail(! append_tpdu_parm(sms, TP_DCS));
    assert_if_fail(! append_tpdu_parm(sms, TP_UDL));
    assert_if_fail(! append_tpdu_parm(sms, TP_UD));

    return do_dessect(sms);
}


/*
 * MMS_STATUS_REPORT type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-MMS TP-SRQ  |
 * +-------------------------+
 * |1. TP-MR                 |
 * +-------------------------+
 * |2 to 12. TP-RA           |
 * +-------------------------+
 * |7. TP-SCTS               |
 * +-------------------------+
 * |7. TP-DT                 |
 * +-------------------------+
 * |1. TP-ST                 |
 * +-------------------------+
 */
static int dessect_status_report(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    assert_if_fail(! append_tpdu_parm(sms, TP_RA));
    assert_if_fail(! append_tpdu_parm(sms, TP_SCTS));
    assert_if_fail(! append_tpdu_parm(sms, TP_DT));
    assert_if_fail(! append_tpdu_parm(sms, TP_ST));

    return do_dessect(sms);
}


/*
 * MMS_COMMAND type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-SRR TP-UDHI |
 * +-------------------------+
 * |1. TP-MR                 |
 * +-------------------------+
 * |1. TP-PID                |
 * +-------------------------+
 * |1. TP-CT                 |
 * +-------------------------+
 * |1. TP-MV                 |
 * +-------------------------+
 * |2 to 12. TP-DA           |
 * +-------------------------+
 * |1. TP-CDL                |
 * +-------------------------+
 * |0 to 156. TP-CD          |
 * +-------------------------+
 */
static int dessect_command(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    assert_if_fail(! append_tpdu_parm(sms, TP_DA));
    assert_if_fail(! append_tpdu_parm(sms, TP_CDL));
    assert_if_fail(! append_tpdu_parm(sms, TP_CD));

    return do_dessect(sms);
}

/*
 * MMS_SUBMIT type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-RD TP-VPF   |
 * |TP-SRR TP-UDHI TP-RP     |
 * +-------------------------+
 * |1. TP-MR                 |
 * +-------------------------+
 * |2 to 12. TP-DA           |
 * +-------------------------+
 * |1. TP-PID                |
 * +-------------------------+
 * |1. TP-DCS                |
 * +-------------------------+
 * |1,2 to 7. TP-VP          |
 * +-------------------------+
 * |1. TP-UDL                |
 * +-------------------------+
 * |0 to 140. TP-UD          |
 * +-------------------------+
 */
static int dessect_submit(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    assert_if_fail(! append_tpdu_parm(sms, TP_DA));
    assert_if_fail(! append_tpdu_parm(sms, TP_PID));
    assert_if_fail(! append_tpdu_parm(sms, TP_DCS));
    assert_if_fail(! append_tpdu_parm(sms, TP_VP));
    assert_if_fail(! append_tpdu_parm(sms, TP_UDL));
    assert_if_fail(! append_tpdu_parm(sms, TP_UD));

    return do_dessect(sms);
}


/*
 * MMS_SUBMIT_REPORT err type PDU format
 * +-------------------------+
 * |1. TP-MTI                |
 * +-------------------------+
 * |1. TP-FCS                |
 * +-------------------------+
 */
static int dessect_submit_report_err(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));
    return do_dessect(sms);
}


/*
 * MMS_SUBMIT_REPORT ack type PDU format
 * +-------------------------+
 * |1. TP-MTI TP-UDHI        |
 * +-------------------------+
 * |1. TP-PI                 |
 * +-------------------------+
 * |7. TP-SCTS               |
 * +-------------------------+
 * |0,1. TP-PID              |
 * +-------------------------+
 * |0,1. TP-DCS              |
 * +-------------------------+
 * |0,1. TP-UDL              |
 * +-------------------------+
 * |0 to 152. TP-UD          |
 * +-------------------------+
 */
static int dessect_submit_report_ack(sms *sms)
{
    assert_if_fail(! __dessect_basic(sms));

    sms->pi = 1;
    assert_if_fail(! append_tpdu_parm(sms, TP_SCTS));
    assert_if_fail(! append_tpdu_parm(sms, TP_PID));
    assert_if_fail(! append_tpdu_parm(sms, TP_DCS));
    assert_if_fail(! append_tpdu_parm(sms, TP_UDL));
    assert_if_fail(! append_tpdu_parm(sms, TP_UD));

    return do_dessect(sms);
}


static const sms_dessector sms_des_tbl[] = {
    dessect_deliver,
    dessect_deliver_report_err,
    dessect_deliver_report_ack,
    dessect_status_report,
    dessect_command,
    dessect_submit,
    dessect_submit_report_err,
    dessect_submit_report_ack,
};


static int dessect_pid(sms *sms)
{
    unsigned char *pdu = sms->pdu + sms->base;
    const tpdu_parm *desc;
    sms_info *info;
    int mti, i, pid, len, sz = sms->len - sms->base;

    for(i = 0, mti = 1 << sms->type; i + 2 <= sz;)  {
        pid = pdu[i++];
        len = pdu[i++];

        if(i + len > sz)  {
            printf("PDU ended prematurely\n");
            break;
        }

        desc = cdma_tpdu_desc(mti, pid, -1);
        if(! desc)  {
            printf("TPDU not found for pid %d\n", pid);
            break;
        }

        if(desc->len > 0 && desc->len != len)  {
            printf("Expected length %d at offset %d but %d\n", 
                   desc->len, i + sms->base - 1, len);
            break;
        }
        info = new_sms_info(desc);
        if(! info)
            break;
        info->offset = i;
        if(info->len < 0)
            info->len = len;
        append_info(sms, info);
        i += len;
    }

    /* if broke prematurely */
    if(i + 2 <= sz)
        return -1;
    return 0;
}

static int dessect_spid(sms *sms)
{
    sms_info *info, *bd = find_sms_info(sms, PID_BD);
    const tpdu_parm *desc;
    const unsigned char *pdu;
    int i, spid, len, sz;

    if(! bd)
        return 0;

    pdu = sms->pdu + sms->base + bd->offset;
    for(i = 0, sz = bd->len; i + 2 <= sz;)  {
        spid = pdu[i++];
        len = pdu[i++];

        if(i + len > sz)  {
            printf("BD PDU ended prematurely\n");
            break;
        }

        desc = cdma_tpdu_desc(MTI_CDMA, PID_BD, spid);
        if(! desc)  {
            printf("TPDU not found for spid %d at %d\n",
                   spid, sms->base + bd->offset + i - 2);
            break;
        }

        if(desc->len > 0 && desc->len != len)  {
            printf("Expected length %d at %d but %d\n", 
                   desc->len, i + sms->base + bd->offset - 1, len);
            break;
        }
        info = new_sms_info(desc);
        if(! info)
            break;
        info->offset = i + bd->offset;
        if(info->len < 0)
            info->len = len;
        append_info(sms, info);
        i += len;
    }

    if(i + 2 <= sz)
        return -1;
    return 0;
}

static int cdma_sms_dessect(sms *sms, int t)
{
    int type = SMS_RESERVED, res;

    assert(sms->hex && sms->pdu && sms->len > 0);

    switch(sms->pdu[0])  {
    case 0:
        type = SMS_CDMA_PP;
        break;
    case 1:
        type = SMS_CDMA_BC;
        break;
    case 2:
        type = SMS_CDMA_AK;
        break;
    default:
        break;
    }

    if(type != SMS_CDMA_PP
       && type != SMS_CDMA_BC
       && type != SMS_CDMA_AK)
        return -1;

    sms->type = type;
    sms->base = 1;

    res = dessect_pid(sms);
    if(! res)
        res = dessect_spid(sms);
    if(! res)  {
        t = cdma_mti_detect(sms, t);
        if(t >= 0 && t <= SMS_RESERVED)
            sms->mti = 1 << t;
        /* no need to do_dessect for CDMA msg */
    }
    return res;
}

static int sms_dessect(sms *sms, int t)
{
    unsigned int type, smsc_len;

    assert(sms->hex && sms->pdu && sms->len > 0);

    if(sms->cdma)
        return cdma_sms_dessect(sms, t);

    if((t == SMS_RESERVED
        || t == SMS_DELIVER
        || t == SMS_STATUS_REPORT)
       && sms->smsc)  {
        smsc_len = sms->pdu[0];
        if(smsc_len > 0)  {
            if(smsc_len < sms->len)  {
                sms->base = smsc_len + 1;
            }else  {
                printf("Invalid SMSC header!\n");
                sms->smsc = 0;
                sms->base = 0;
            }
        }else  {
            sms->smsc = 0;
            sms->base = 1;
        }
    }else  {
        sms->smsc = 0;
    }

    for(;;)  {
        type = mti_detect(sms->pdu + sms->base, t);
        if(type != SMS_DELIVER && type != SMS_STATUS_REPORT && sms->smsc)  {
            printf("Should not have a SMSC!\n");
            sms->smsc = 0;
            sms->base = 0;
            continue;
        }
        break;
    }

    if(type >= 0 && type < SMS_RESERVED)  {
        sms->mti = 1 << type;
        return sms_des_tbl[type](sms);
    }

    return -1;
}


static inline void sms_dessect_end(sms *sms)
{
    sms_clear(sms);
}

static void pre_dump(const char *hex, des_ctx *cfg)
{
    const char *prefix = "DESSECTING:";
    int i, len = strlen(hex);

#if 1
    PRINT("%s%s\n", prefix, hex);
#else
    if(len < 80 - strlen(prefix))  {
        PRINT("%s%s\n", prefix, hex);
        return;
    }

    for(i = 0; i < len;)  {
        if(i == 0)  {
            PRINT("%s%.*s\n", prefix, 80 - strlen(prefix), hex);
            i += 80 - strlen(prefix);
        }else  {
            if(len - i > 80)  {
                PRINT("%.*s\n", 80, hex + i);
                i += 80;
            }else  {
                PRINT("%s\n", hex + i);
                break;
            }
        }
    }
#endif
}


static void sms_info_dump(sms *sms, des_ctx *cfg, sms_info *info, int base)
{
    const tpdu_parm *desc = info->handler;
    const char *val = "";
    unsigned int t, idx;

    if(! desc->desc && ! desc->des_func)
        return;

    if(desc->desc && info->shift >= 0 && info->size > 0)  {
        t = sms->pdu[base + info->offset];
        idx = ((t >> info->shift) & ((1 << info->size) - 1));
        val = desc->desc[idx];
    }
    DES_PRINT("%-35s:%s\n", tpdu_id_name[desc->id], val);

    if(desc->des_func)
        desc->des_func(sms, cfg, desc, sms->pdu + base + info->offset, info->len);

    /* not a bitmask dessector */
    if(info->shift < 0 && cfg->raw)
        HEX_DUMP(sms->pdu + base + info->offset, info->len);
}

static void sms_dump(sms *sms, des_ctx *cfg)
{
    sms_info *info;

    PRINT("===================================================================\n");
    if(sms->cdma)
        PRINT("%-35s:%s\n", "MESSAGE TYPE", cdma_msg_type[sms->type - SMS_CDMA_PP]);
    if(sms->smsc && sms->smsc_info)
        sms_info_dump(sms, cfg, sms->smsc_info, 0);

    for(info = sms->info; info; info = info->nxt)
        sms_info_dump(sms, cfg, info, sms->base);
    PRINT("===================================================================\n");
}


int main(int argc, char *argv[])
{
    int i, c, idx, type = SMS_RESERVED;
    const char *tp_list = NULL, *type_name = NULL;
    int smsc = 1, cdma = 0;
    des_ctx cfg;
    sms sms;

    BUILD_FAIL_IF(NUM_TP != ARRAYSIZE(tpdu_id_name) + 1);
    BUILD_FAIL_IF(128 != ARRAYSIZE(gsm_alphabet));
    BUILD_FAIL_IF(NUM_IEI != ARRAYSIZE(iei_name));

    init_default_ctx(&cfg);

    for(;;)  {
        static struct option opts[] = {
            {"cdma", 0, NULL, 'c'},
            {"full", 0, NULL, 'f'},
            {"simple", 0, NULL, 's'},
            {"help", 0, NULL, 'h'},
            {"tpdu", 1, NULL, 'p'},
            {"list", 0, NULL, 'l'},
            {"type", 1, NULL, 't'},
            {"no-smsc", 0, NULL, 'n'},
            {"raw", 0, NULL, 'r'},
            {"version", 0, NULL, 'v'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "cfshp:lt:nrv", opts, &idx);
        if(-1 == c)
            break;

        switch(c)  {
        case 'c':
            cdma = 1;
            break;
        case 'f':
            /* nothing to do, the default */
            break;
        case 's':
            /* just print user data */
            memset(cfg.tp_cfg, 0, sizeof(cfg.tp_cfg));
            cfg.tp_cfg[TP_MTI] = 1;
            cfg.tp_cfg[TP_OA] = 1;
            cfg.tp_cfg[TP_DA] = 1;
            cfg.tp_cfg[TP_SCTS] = 1;
            cfg.tp_cfg[TP_UD] = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'p':
            if(! optarg)  {
                printf("An argument required for -t!\n");
                usage(argv[0]);
                exit(-1);
            }
            tp_list = optarg;
            break;
        case 'l':
            dump_des_opt();
            exit(0);
        case 't':
            if(! optarg)  {
                printf("An argument required for -t!\n");
                usage(argv[0]);
                exit(-1);
            }
            type_name = optarg;
            break;
        case 'n':
            smsc = 0;
            break;
        case 'r':
            cfg.raw = 1;
            break;
        case 'v':
            version();
            exit(0);
        default:
            usage(argv[0]);
            exit(-1);
            break;
        }
    }

    if(optind >= argc)  {
        printf("SMS PDU list expected!\n");
        usage(argv[0]);
        exit(-1);
    }

    if(tp_list)
        des_ctx_cfg(&cfg, tp_list);
    if(type_name)  {
        if(! cdma)  {
            for(i = 0; i < ARRAYSIZE(gsm_sms_type); i++)  {
                if(! strcasecmp(type_name, gsm_sms_type[i]))  {
                    type = i;
                    break;
                }
            }
        }else  {
            for(i = 0; i < ARRAYSIZE(cdma_sms_type); i++)  {
                if(! strcasecmp(type_name, cdma_sms_type[i]))  {
                    type = i + SMS_CDMA_DELIVER;
                    break;
                }
            }
        }
        if(type == SMS_RESERVED)  {
            printf("Invalid SMS type specified:%s\n", type_name);
            usage(argv[0]);
            exit(-1);
        }
    }


    for(i = optind; i < argc; i++)  {
        if(! argv[i] || ! argv[i][0])
            continue;

        if(! sms_dessect_begin(&sms, argv[i], cdma, smsc))  {
            pre_dump(sms.hex, &cfg);
            if(! sms_dessect(&sms, type))  {
                sms_dump(&sms, &cfg);
            }else  {
                __PRINT(&cfg, "Invalid SMS PDU to dessect!\n");
                ___hex_dump(0, sms.pdu, sms.len);
            }
            sms_dessect_end(&sms);
        }
    }

    return 0;
}

