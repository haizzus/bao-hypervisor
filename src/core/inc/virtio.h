/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      João Peixoto <joaopeixotooficial@gmail.com>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#ifndef __VIRTIO_H__
#define __VIRTIO_H__

#include <bao.h>
#include <emul.h>
#include <list.h>
#include <vm.h>

/*!
 * @struct  virtio_device
 * @brief   Contains all the information of a VirtIO device          
 */
struct virtio_device {
    uint64_t va;                    // Virtual address that will be used to access the MMIO registers of the device
    size_t size;                    // Size of the MMIO region (usually 0x200)
    //uint64_t shmem_id;            // Shared memory ID to be used
    irqid_t interrupt;              // Used to notify the Backend when an access to a VirtIO MMIO register is performed and to notify the Frontend (Used Buffer Notification or Configuration Change Notification)
    uint64_t virtio_id;             // VirtIO ID (used to connect each frontend driver to the backend device)
    int backend_id;                 // Contains the ID of the backend device (Generated automatically by virtio_init function) 
    int backend_vm_id;              // Contains the ID of the VM where the backend driver is located (Generated automatically by virtio_init function)
    int frontend_vm_id;             // Contains the ID of the VM where the frontend driver is located (Generated automatically by virtio_init function)
    int frontend_id;                // Contains the ID of the frontend driver (Generated automatically by virtio_init function)
    bool is_back_end;               // Specifies if the VM will contain the VirtIO backend driver
    bool pooling;                   // Delineate if the backend execution mode is going to be pooling or by interrupts
    int priority;                   // Priority (higher number means lower priority) of the driver (Used to schedule the backend driver)
    int device_type;                // Device type (Used to identify the real physical device) 
};

/*!
 * @fn              virtio_init
 * @brief           Responsible to initialize the VirtIO devices
 * @return          void     
 */
void virtio_init();

/*!
 * @fn              virtio_assign_cpus
 * @brief           Responsible to assign the frontend and backend CPUs to the VMs that contain VirtIO instances
 * @return          void     
 */
void virtio_assign_cpus(struct vm* vm);

/*!
 * @fn              virtio_hypercall
 * @brief           Handle the VirtIO hypercall
 * @note            The VirtIO hypercall is used by the backend to request or send information
 * @param   arg0    First argument of the hypercall
 * @param   arg1    Second argument of the hypercall
 * @param   arg2    Third argument of the hypercall
 * @return          unsigned long     
 */
unsigned long virtio_hypercall(unsigned long arg0, unsigned long arg1, unsigned long arg2);

/*!
 * @fn                      virtio_mmio_emul_handler
 * @brief                   Handle every MMIO register access of a VirtIO device
 * @note                    Executed by the frontend CPU
 * @param   emul_access     Structure that contains the information of the MMIO register access
 * @return                  bool     
 */
bool virtio_mmio_emul_handler(struct emul_access *);

/*!
 * @struct  virtio_mmio_reg
 * @brief   Contains all the VirtIO MMIO registers 
 * @note    The driver MUST only use 32 bit wide and aligned reads and writes to access the control registers described
 *          in table 4.1. For the device-specific configuration space, the driver MUST use 8 bit wide accesses for 8 bit
 *          wide fields, 16 bit wide and aligned accesses for 16 bit wide fields and 32 bit wide and aligned accesses for
 *          32 and 64 bit wide fields.
 */
struct virtio_mmio_reg{
    uint32_t MagicValue;        // offset 0x000
    uint32_t Version;           // offset 0x004
    uint32_t DeviceID;          // offset 0x008
    uint32_t VendorID;          // offset 0x00c
    uint32_t DeviceFeatures;    // offset 0x010
    uint32_t DeviceFeaturesSel; // offset 0x014
    uint8_t pad0[0x020 - 0x018];// padding 
    uint32_t DriverFeatures;    // offset 0x020
    uint32_t DriverFeaturesSel; // offset 0x024
    uint8_t pad1[0x030 - 0x028];// padding 
    uint32_t QueueSel;          // offset 0x030
    uint32_t QueueNumMax;       // offset 0x034
    uint32_t QueueNum;          // offset 0x038
    uint8_t pad2[0x044 - 0x03c];// padding 
    uint32_t QueueReady;        // offset 0x044
    uint8_t pad3[0x050 - 0x048];// padding 
    uint32_t QueueNotify;       // offset 0x050
    uint8_t pad4[0x060 - 0x054];// padding 
    uint32_t InterruptStatus;   // offset 0x060
    uint32_t InterruptACK;      // offset 0x064
    uint8_t pad5[0x070 - 0x068];// padding 
    uint32_t Status;            // offset 0x070
    uint8_t pad6[0x080 - 0x074];// padding 
    // 64 bit long physical address
    uint32_t QueueDescLow;      // offset 0x080
    uint32_t QueueDescHigh;     // offset 0x084
    uint8_t pad7[0x090 - 0x088];// padding 
    // 64 bit long physical address
    uint32_t QueueDriverLow;    // offset 0x090   
    uint32_t QueueDriverHigh;   // offset 0x094
    uint8_t pad8[0x0a0 - 0x098];// padding
    // 64 bit long physical address
    uint32_t QueueDeviceLow;    // offset 0x0a0
    uint32_t QueueDeviceHigh;   // offset 0x0a4
    uint8_t pad9[0x0ac - 0x0a8];// padding
    uint32_t SHMSel;            // offset 0x0ac
    // 64 bit long physical address
    uint32_t SHMLenLow;         // offset 0x0b0
    uint32_t SHMLenHigh;        // offset 0x0b4
    // 64 bit long physical address
    uint32_t SHMBaseLow;        // offset 0x0b8
    uint32_t SHMBaseHigh;       // offset 0x0bc
    uint8_t pad10[0x0fc - 0x0c0];// padding
    uint32_t ConfigGeneration;  // offset 0x0fc
    uint32_t Config;            // offset 0x100
} __attribute__((__packed__, aligned(0x1000)));

#endif /* __VIRTIO_H__ */