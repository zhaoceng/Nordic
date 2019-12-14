#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>
#include "log.h"

void Create_Static_OOB_AuthValue(uint8_t *AuthValue, uint8_t *pid, const uint8_t *con_mac_address, uint8_t *p_secret);

#endif   // SHA256_H