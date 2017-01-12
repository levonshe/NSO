/**************************************************************************

Copyright (c) 2006-2016, Silicom
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 3. Neither the name of the Silicom nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/
#ifndef _SLCMI_IOCTL__H
#define _SLCMI_IOCTL__H
#ifndef __KERNEL__
#include <stdint.h>
#include <linux/types.h>
typedef uint8_t byte;
#else
#include <linux/fs.h>
#include <asm/uaccess.h> /* for get_user and put_user */
typedef u8 byte;
#endif // __KERNEL


#define A0_VENDOR_Finisar  0x009065 // Finisar registered Vendor UOI IEEE vendor ID
#define A0_VENDOR_Eoptolink 0x999999 // Eoptolink  registered Vendor OUI - not present in GBIC
#define A0_VENDOR_Riverbed  0x000eb6 // Riverbed registered Vendor UOI IEEE vendor ID
#define A0_VENDOR_Avago     0x00176a // Avago registered Vendor UOI IEEE vendor ID
#define A0_VENDOR_Amphenol  0x78A714 // Amphenol registered Vendor UOI IEEE vendor ID
#define A0_VENDOR_SOURCE_PHOTONICS  0x001f22
#define A0_VENDOR_FCI       0xFC7CE7  // Product FCi  board GC-12-622 , Vendor name FCI El

#define SFP_VENDOR_POS 20
#define QSFP_VENDOR_POS 148
#define SFP_FORM_FACTOR 0x3
#define QSFP_FORM_FACTOR 0xC
typedef enum {
    IF_SCAN ,
    GET_DEV_NUM ,
    GET_SLCM_OEM_INFO ,
    GET_SLCM_PROD_INFO ,
    GET_SLCM_SFP_A0 ,
    GET_SFP_DIAG,
    GET_SLCM_SFP,
   
    GET_SFP_SIGN,
    GET_SLCM_FW_INT_VER,
    GET_SLCM_QSFP_A0,
   
    GET_SLCM_QSFP_U0,
    GET_SLCM_QSFP_U1,
    GET_SLCM_QSFP_U2,
    GET_SLCM_QSFP_U3,
    
   } CMND_TYPE_SD ;

/*
* The major device number. We can't rely on dynamic
* registration any more, because ioctls need to know
* it.
*/


#define MAGIC_NUM 'J'  
/*
 * silicom 	Prod info will always start at offset+0x0020
 *@sign "PRDi" ascii characters (for PRoDuct Information), if signature is not available then prod info is not available
 *@prod_type
 *@num_ports
 *@speed
 *@media_type
 *@nic_type
 */

typedef struct _slcm_prod_info_t {
        byte sign[4];
        byte prod_type[1];
        byte num_ports[1];
        byte speed[1];
        byte media_type[1];
        byte nic_type[2];
        byte oem_addr[2];
        byte data[4];
        byte name[28];
        byte rev[4];
        byte fw_ver[2];
        byte sn[14]; /* serial number */
        byte track[16];
  
} slcm_prod_info_t;

/*
 * Product and OEM info in product EEPROM (Identifier Section/Srting
 * 
 * @vtid Section Identifier Descriptor (must be 82h) 
 * @oem_len Identifier section length, in Big endian
 * @vers1 Most-significant bytes of the software version, Ascii
   @char cons 0x76
   @vers2 Less-significant byte of the software version, Ascii
 * @code "XX" (Chars with the OEM Silicom code - XX we use)
 * @size OEM data size in bytes
 * @str "XXXX" customer specific code. If not available write 0xFF x 4
 * @data1, @data2 General OEM data per customer definition, if not used then put 0xFF x 16
 */
typedef union _slcm_oem_info_t {
   
    struct {
        //byte vtid;
        //u16 oem_len
        //char vers1[2] 
        //char cons 0x76
        //char vers2 
       
        char code[2];
        char size[2];
        char str[4];
        byte data1[4]; // General OEM data per customer definition, if not used then put 0xFF x 16
        byte data2[4];
	char version[5]; // Actuallu this is vers1 .. vers2 5 bytes above after vtid and oem_len  
    } oem_info;
} slcm_oem_info_t;  

typedef union _slcm_oem_prod_info_t {
    unsigned short info[(sizeof(slcm_oem_info_t) + sizeof(slcm_prod_info_t))/2]; //	For Byte Access

   struct{
       slcm_oem_info_t oem_info;
       slcm_prod_info_t prod_info;
   } op_info;
} slcm_oem_prod_info_t;


typedef struct __sfp_info{
        byte ident[1];
        byte ident_ex[1];
        byte con[1];
        byte trans[8];
        byte code[1];
        byte br[1];
        byte rate_ident[1];
        byte len0[1];
        byte len1[1];
        byte len2[1];
        byte len3[1];
        byte len4[1]; 
        byte len5[1];
        char vendor_name[16];
        byte trans1[1];
        byte vendor_oui[3];
        byte vendor_pn[16];
        byte vendor_rev[4];
        byte wavelength[2];
        byte unalloc[1];
        byte cc_base[1];
        byte opt[2];
        byte br_max[1];
        byte br_min[1];
        byte vendor_sn[16];
        byte date_code[8];
        byte mon_type[1];
        byte enh_opt[1];
        byte compl[1];
        byte cc_ext[1];
    }  sfp_info_t ;
   

typedef union _slcm_sfp_a0_t {
    byte dump[96]; //	For Byte Access
    sfp_info_t info;    
} slcm_sfp_a0_t;

typedef struct __qspf_info{  // SFF 8636 page 24
        byte ident[1];
        byte ident_ex[1];
        byte module_monitors[12];
	byte channel_monitors[48];
        byte reserved1[4];
        byte control[12];
        byte reserved2[2];
	byte module_channel_mask[7];
	byte reserved3[12];
        byte password_change[4];
        byte password[4];
        byte page_select_byte[1];
        
    }  qsfp_lower_page_t; // Page A0

typedef struct _qspf_upper_page0_t_{
   byte base_id_fields[64];
   byte base_extended_id[32];
   byte vendor_specific[32];
   } qspf_upper_pageU0_t;

typedef 
union {
  uint8_t dump[128];
  qspf_upper_pageU0_t page_U0;
} qspf_upper_page0_t;

typedef struct _qspf_upper_page1_{
   byte cc_apps[1];
   byte ast_table_len[1];
   // Array of application_entries fills structure up to 256 byte
   uint16_t application_entries[256/2 -1 ];
}  qspf_upper_page1;
   
typedef struct _qspf_info_t_page2_{
   byte eprom_data[128];
   
   }  qspf_upper_page2;
   

   
typedef struct _qspf_info_t_page3_{
   byte ModuleThresshold[48];
   byte ChannelThresshold[48];
   byte page3_reserved[2];
   byte VendorSpecificChannelControls[16];
   byte ChannelMonitorsMasks[12];
   byte page3_reserved2[2];
   
 }  qspf_upper_page3_t;
 
 typedef union {
   byte eprom_data[128];
   qspf_upper_page3_t info;
   }  qspf_upper_page3; 
   
typedef union __slcm_qspf_a0_t { // QSFP-28 SFPF 8636 Spec
      byte dump[256]; //	For Byte Access
      qsfp_lower_page_t qspf_info;    
} slcm_qsfp_a0_t;


typedef   struct _sclm_sfp_diag{
        byte temp_h_alarm[2];
        byte temp_l_alarm[2];
        byte temp_h_warn[2];
        byte temp_l_warn[2];

        byte volt_h_alarm[2];
        byte volt_l_alarm[2];
        byte volt_h_warn[2];
        byte volt_l_warn[2];
        
        byte bias_h_alarm[2];
        byte bias_l_alarm[2];
        byte bias_h_warn[2];
        byte bias_l_warn[2];

        byte txpwr_h_alarm[2];
        byte txpwr_l_alarm[2];
        byte txpwr_h_warn[2];
        byte txpwr_l_warn[2];

        byte rxpwr_h_alarm[2];
        byte rxpwr_l_alarm[2];
        byte rxpwr_h_warn[2];
        byte rxpwr_l_warn[2];

        byte unalloc[16];

        byte rxpwr_4[4];
        byte rxpwr_3[4];
        byte rxpwr_2[4];
        byte rxpwr_1[4];
        byte rxpwr_0[4];

        byte tx_l_s[2];
        byte tx_l_o[2];

        byte txpwr_s[2];
        byte txpwr_o[2];

        byte t_s[2];
        byte t_o[2];

        byte v_s[2];
        byte v_o[2];

        byte unalloc1[3];
        byte cs[1];

        byte temp_m[1];
        byte temp_l[1];
        byte vcc_m[1];
        byte vcc_l[1];
        byte bias_m[1];
        byte bias_l[1];

        byte tx_pwr_m[1];
        byte tx_pwr_l[1];
        byte rx_pwr_m[1];
        byte rx_pwr_l[1];
        byte unalloc2[4];
        byte status[1];
} sfp_diag_A2_t;
   

typedef union _slcm_sfp_a2_t {
    byte dump[120]; //	For Byte Access
    sfp_diag_A2_t info;
 
} slcm_sfp_a2_t;

typedef struct _sfp_a2_eprom {
    byte erprom[120]; // Bytes 128-248 of SFP A2 page
    byte vendor_specific[8];
} sfp_a2_eprom_t;

/*
 *@struct slcm_cmd : passed woth ioctl() input/output user data area
 *@in_param - select device, pass command to execute
 *@data - output data, mostly dump of GBIC eeprom
 */
struct slcm_cmd {
    int status;
    byte in_param[8];
    byte out_param[8];
    byte data[256]; // size of SFP .QSFP pages (lower and upper memory)
};


#define IOCTL_TX_MSG(cmd) _IOWR(MAGIC_NUM, cmd, struct slcm_cmd)

#define DEVICE_NODE "/dev/slcm0"
#define DEVICE_NAME "slcm"


#endif

