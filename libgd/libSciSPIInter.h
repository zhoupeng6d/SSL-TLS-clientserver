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
#ifndef LIB_SCI_SPI_INTER_H__
#define LIB_SCI_SPI_INTER_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

//waiting timing
#define LIB_SCI_SPI_ATP_MAX			5000				//ms

/*******************************************
             IC卡处理状态
 *******************************************/
#define ICC_SUCCESS                   0
#define ICC_VCCMODEERR            (-2500)       /* 电压模式错误 */
#define ICC_INPUTSLOTERR          (-2501)       /* 选择通道口错误 */
#define ICC_VCCOPENERR            (-2502)       /* */
#define ICC_ICCMESERR             (-2503)       /* 卡通讯失败 */

#define ICC_T0_TIMEOUT            (-2200)       /* 等待卡片响应超时  */
#define ICC_T0_MORESENDERR        (-2201)       /* 重发错误 */
#define ICC_T0_MORERECEERR        (-2202)       /* 重收错误 */
#define ICC_T0_PARERR             (-2203)       /* 字符奇偶错误 */
#define ICC_T0_INVALIDSW          (-2204)       /* 状态字节无效 */

#define ICC_DATA_LENTHERR         (-2400)       /* 数据长度错误  */
#define ICC_PARERR                (-2401)       /* 奇偶错误      */
#define ICC_PARAMETERERR          (-2402)       /* 参数值为空 */
#define ICC_SLOTERR               (-2403)       /* 卡通道错误   */
#define ICC_PROTOCALERR           (-2404)       /* 协议错误     */
#define ICC_CARD_OUT              (-2405)       /* 卡拔出       */
#define ICC_NO_INITERR            (-2406)       /* 没有初始化   */
#define ICC_ICCMESSOVERTIME       (-2407)       /* 卡通讯超时 */

#define ICC_ATR_TSERR             (-2100)       /* 正反向约定错误，TS错误*/
#define ICC_ATR_TCKERR            (-2101)       /* 复位校验（T=1，TCK错误）错误    */
#define ICC_ATR_TIMEOUT           (-2102)       /* ??????    */
#define ICC_TS_TIMEOUT            (-2115)       /* ??????    */
#define ICC_ATR_TA1ERR            (-2103)       /* TA1??         */
#define ICC_ATR_TA2ERR            (-2104)       /* TA2??         */
#define ICC_ATR_TA3ERR            (-2105)       /* TA3??         */
#define ICC_ATR_TB1ERR            (-2106)       /* TB1??         */
#define ICC_ATR_TB2ERR            (-2107)       /* TB2??         */
#define ICC_ATR_TB3ERR            (-2108)       /* TB3??         */
#define ICC_ATR_TC1ERR            (-2109)       /* TC1??         */
#define ICC_ATR_TC2ERR            (-2110)       /* TC2??         */
#define ICC_ATR_TC3ERR            (-2111)       /* TC3??         */
#define ICC_ATR_TD1ERR            (-2112)       /* TD1??         */
#define ICC_ATR_TD2ERR            (-2113)       /* TD2??         */
#define ICC_ATR_LENGTHERR         (-2114)       /* ATR??????  */

#define ICC_T1_BWTERR             (-2300)       /* T=1????????  */
#define ICC_T1_CWTERR             (-2301)       /* T=1????????  */
#define ICC_T1_ABORTERR           (-2302)       /* ??(ABORT)???? */
#define ICC_T1_EDCERR             (-2303)       /* ?????(EDC)?? */
#define ICC_T1_SYNCHERR           (-2304)       /* ??????*/
#define ICC_T1_EGTERR             (-2305)       /* ????????    */
#define ICC_T1_BGTERR             (-2306)       /* ????????    */
#define ICC_T1_NADERR             (-2307)       /* ???NAD??       */
#define ICC_T1_PCBERR             (-2308)       /* ??PCB??         */
#define ICC_T1_LENGTHERR          (-2309)       /* ??LEN??         */
#define ICC_T1_IFSCERR            (-2310)       /* IFSC??            */
#define ICC_T1_IFSDERR            (-2311)       /* IFSD??            */
#define ICC_T1_MOREERR            (-2312)       /* ?????????  */
#define ICC_T1_PARITYERR          (-2313)       /* ??????*/
#define ICC_T1_INVALIDBLOCK       (-2314)       /* ?????*/

//sci spi context
typedef struct {
	//IFSC
	uint8_t ucIFSC;								//
	
	//EDC type
	uint8_t ucEDCType;						//0-LRC 1-CRC
	
	//ter_pcb
	uint8_t ucTerPCB;							//ter will send the nb of next I block
	
	//card pcb
	uint8_t ucCardPCB;							//card send the nb of last I block
	
	//WTX
	uint8_t ucWTX;								//wtx number
	
	//BWT
	uint16_t usBWT;								//ms

}lib_sci_spi_context;

//context
extern lib_sci_spi_context stSciSPICxt;

#endif  	//LIB_SCI_SPI_INTER_H__

