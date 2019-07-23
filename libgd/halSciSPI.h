#ifndef __HAL_SCI_SPI_H__
#define __HAL_SCI_SPI_H__

#ifdef __cplusplus
extern "C" {
#endif

int libSciSPIInit(int ch);
int libSciSPIFree();
int libSciSPIIccCommand(unsigned char *tbuf, unsigned short tlen,
                        unsigned char *rbuf, unsigned short *p_rlen);

#ifdef __cplusplus
}
#endif
#endif
