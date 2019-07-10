

#ifndef __SECCPT__
#define __SECCPT__

#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <ql_spi.h>

#ifdef  __cplusplus
extern "C" {
#endif

//certification type define
#define CA_TYPE						0x01
#define CLIENT_TYPE					0x02

int setSPI_fid(uint16_t fid);
uint8_t readCert(const char *filename, uint8_t cert_type, uint8_t cid);

#ifdef  __cplusplus
	}
#endif

#endif
