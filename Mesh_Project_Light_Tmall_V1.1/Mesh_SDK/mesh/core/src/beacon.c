/* Copyright (c) 2010 - 2018, Nordic Semiconductor ASA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "advertiser.h"
#include "packet.h"
#include "log.h"
#include "nrf_mesh.h"
#include "prov_beacon.h"
#include "nrf_mesh_assert.h"
#include "net_beacon.h"

#include "beacon.h"

/************************
 * Packet Type Typedefs *
 ************************/

/** Generic beacon packet */
typedef struct
{
    uint8_t beacon_type;  /**< Beacon type, see @ref BEACON_TYPE */
    uint8_t payload[];    /**< Beacon payload. */
} beacon_packet_t;
/**************/
/* Public API */
/**************/
adv_packet_t * beacon_create(advertiser_t * p_adv, uint8_t beacon_type, const void* p_payload, uint8_t payload_len)
{
    if (p_adv == NULL || p_payload == NULL || payload_len == 0 ||
        beacon_type == BEACON_TYPE_INVALID || payload_len > BEACON_DATA_MAXLEN)
    {
        return NULL;
    }
    uint8_t beacon_len = BEACON_PACKET_AD_LEN_OVERHEAD + payload_len;
    adv_packet_t * p_packet = advertiser_packet_alloc(p_adv, BLE_AD_DATA_OVERHEAD + beacon_len);   	//申请广播包内存

    if (p_packet != NULL)
    {
        ble_ad_data_t * p_ad_data = (ble_ad_data_t *) &p_packet->packet.payload[0];
        p_ad_data->length = beacon_len;																															//Mesh Beacon 广播包中的Len
        p_ad_data->type = AD_TYPE_BEACON;																														//Mesh Beacon 广播包中的0x2B
        beacon_packet_t* p_beacon = (beacon_packet_t*) p_ad_data->data;															//Mesh Beacon 广播包中的Beacon type + Beacon Data
        p_beacon->beacon_type = beacon_type;																												//Mesh Beacon 广播包中的Beacon type
        memcpy(&p_beacon->payload[0], p_payload, payload_len);																			//Mesh Beacon 广播包中的Beacon Data
    }

    return p_packet;
}

uint32_t beacon_packet_in(const uint8_t * p_beacon_data, uint8_t data_len, const nrf_mesh_rx_metadata_t * p_packet_meta)
{
    NRF_MESH_ASSERT(p_beacon_data != NULL);

    if (data_len < BEACON_PACKET_OVERHEAD)
    {
        return NRF_ERROR_INVALID_LENGTH;
    }
    beacon_packet_t * p_beacon = (beacon_packet_t*) p_beacon_data;

    const uint8_t beacon_data_len = data_len - BEACON_PACKET_OVERHEAD;
    uint32_t status = NRF_SUCCESS;
    switch (p_beacon->beacon_type)
    {
        case BEACON_TYPE_UNPROV:
            prov_beacon_unprov_packet_in(p_beacon->payload, beacon_data_len, p_packet_meta);
            break;
        case BEACON_TYPE_SEC_NET_BCAST:
            net_beacon_packet_in(p_beacon->payload, beacon_data_len, p_packet_meta);
            break;

        default:
            __LOG(LOG_SRC_BEACON, LOG_LEVEL_WARN, "Got unrecognised beacon ID: 0x%.02x.\n", p_beacon->beacon_type);
            __LOG_XB(LOG_SRC_BEACON, LOG_LEVEL_INFO, "Beacon raw data:", &p_beacon->payload[0], data_len);
            status = NRF_ERROR_INVALID_DATA;
            break;
    }

    return status;
}
