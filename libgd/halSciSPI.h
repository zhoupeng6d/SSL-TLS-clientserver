/* Copyright (c)  2017 Giesecke & Devrient Group. All Rights Reserved.
 *
 * The information contained herein is property of Giesecke & Devrient Group ASA.
 * Terms and conditions of usage are described in detail in Giesecke & Devrient Group
 * STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */
 
#ifndef HAL_SCI_SPI_H__
#define HAL_SCI_SPI_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

//CMD/RSP NAD
#define HAL_SCI_SPI_CMD_NAD			0x21
#define HAL_SCI_SPI_RSP_NAD			0x12

//Polling timing
#define SCI_SPI_POLLING		5  			//1ms
//GPIO for SE vcc control
#define OPT_SYS_GPIO        79          //sys gpio79 map to sim7600 gpio 41,
                                        //   as the power control pin of SE
#define ATP_LEN 0x25

bool libSciSPIReset(uint16_t fd,uint8_t *puc_atr, uint8_t *puc_atr_len);

bool libSciSPIIccCommand(uint16_t fd,uint8_t *puc_apdu_send, uint16_t us_apdu_length, uint8_t *puc_apdu_rsp, uint16_t *pus_resp_length);


#endif		//HAL_SCI_SPI_H__

