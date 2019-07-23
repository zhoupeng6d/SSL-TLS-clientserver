#ifndef __SECCPT__
#define __SECCPT__

#include <stdint.h>
#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

//certification type define
#define CA_TYPE     0x01
#define CLIENT_TYPE 0x02

uint8_t readCert( char *filename, uint8_t cert_type, uint8_t cid);

#ifdef __cplusplus
}
#endif

#endif

