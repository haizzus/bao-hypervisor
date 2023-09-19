/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      João Peixoto <pg50479@alunos.uminho.pt>
 *      Nuno Capela <a84981@alunos.uminho.pt>
 *      João Rodrigo <a85218@alunos.uminho.pt>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#include <virtio.h>
#include <cpu.h>
#include <vm.h>
#include <hypercall.h>
#include <ipc.h>
#include <objpool.h>
#include <config.h>

/*!
 * @enum
 * @brief   VirtIO hypercall operations      
 */
enum {
    VIRTIO_WRITE_OP,       // Write operation
    VIRTIO_READ_OP,        // Read operation 
    VIRTIO_ASK_OP,         // Ask operation               
    VIRTIO_POOLING_OP,     // Pooling operation     
    VIRTIO_INTERRUPT_OP    // Interrupt operation (used event notification -> backend buffer used on the virtqueue)
};

/*!
 * @enum
 * @brief   VirtIO cpu_msg events      
 */
enum {
    VIRTIO_WRITE_NOTIFY,        // Write notification
    VIRTIO_READ_NOTIFY,         // Read notification
    VIRTIO_NOTIFY_BACKEND_INT,  // Notify backend by interrupt
    VIRTIO_NOTIFY_BACKEND_POOL, // Notify backend by pooling
    VIRTIO_INJECT_INTERRUPT     // Inject interrupt into the backend
};

struct list virtio_device_pooling_list;
struct list virtio_device_list;

OBJPOOL_ALLOC(virtio_device_pooling_cache, struct virtio_pooling_params, sizeof(struct virtio_pooling_params));
OBJPOOL_ALLOC(virtio_device_cache, struct virtio_device_params, sizeof(struct virtio_device_params));

static void virtio_handler(uint32_t, uint64_t);

// create the handler for the cpu_msg
CPU_MSG_HANDLER(virtio_handler, VIRTIO_CPUMSG_ID);

void virtio_init()
{
    uint32_t virtiodevicelist_size = 0;

    // get the number of virtio devices
    for (int vm_id = 0; vm_id < config.vmlist_size; vm_id++)
    {
        struct vm_config *vm_config = &config.vmlist[vm_id]; 
        for (int i = 0; i < vm_config->platform.virtiodevices_num; i++) 
        {
            if (vm_config->platform.virtiodevices[i].is_back_end)
                virtiodevicelist_size++;
        }
    }
    
    int backend_devices[virtiodevicelist_size];

    objpool_init(&virtio_device_cache);
    list_init(&virtio_device_list);

    objpool_init(&virtio_device_pooling_cache);
    list_init(&virtio_device_pooling_list);

    // create a list with all the virtio devices
    for (int i = 0; i < virtiodevicelist_size; i++) 
    {
        struct virtio_device_params *node = objpool_alloc(&virtio_device_cache);
        node->id = i;
        list_push(&virtio_device_list, (node_t*)node);
        backend_devices[i] = -1;
    };

    // assign the backend and frontend ids
    for (int vm_id = 0; vm_id < config.vmlist_size; vm_id++)
    {
        struct vm_config *vm_config = &config.vmlist[vm_id];
        for (int i = 0; i < vm_config->platform.virtiodevices_num; i++) 
        {
            struct virtio_device *dev = &vm_config->platform.virtiodevices[i];
            if(dev->is_back_end)
            {
                if (backend_devices[dev->device_id] != -1) 
                {
                    for (int i = 0; i < virtiodevicelist_size; i++) 
                    {
                        objpool_free(&virtio_device_cache, (struct virtio_device_params*)list_pop(&virtio_device_list));
                    }
                    ERROR("Failed to link backend to the device, more than one back-end was atributed to the VirtIO device %d", dev->device_id);
                }
                else {
                    dev->backend_id = vm_id;
                    backend_devices[dev->device_id] = vm_id;
                }
            }
            else
                dev->frontend_id = vm_id;
        }
    }

    // check if there is only one backend for each virtio device
    for (int i = 0; i < virtiodevicelist_size; i++)
    {
        if(backend_devices[i] == -1)
        {
            for (int i = 0; i < virtiodevicelist_size; i++) 
            {
                objpool_free(&virtio_device_cache, (struct virtio_device_params*)list_pop(&virtio_device_list));
            }
            ERROR("There is no backend for the VirtIO device %d", i);
        } 
    }
}

void virtio_assign_backend_cpu(struct vm* vm)
{
    list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
    {
        if (vm->virtiodevices[virtio_device->id].backend_id == cpu()->vcpu->vm->id)
            virtio_device->backend_cpu_id = cpu()->id;
    }
}

/*!
 * @fn              virtio_hypercall_w_r_operation
 * @brief           Performs a write or read operation in a VirtIO device
 * @note            Executed by the backend VM
 * @param dev_id    Contains the device id
 * @param reg_off   Contains the MMIO register offset
 * @param value     Contains the register value
 * @return          true if the operation was successful, false otherwise     
 */
static bool virtio_hypercall_w_r_operation(unsigned long dev_id, unsigned long reg_off, unsigned long value)
{
    list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
    {
        if(virtio_device->id == dev_id)
        {
            // if the register is wrong returns false
            if(virtio_device->reg_off != reg_off)
                return false;

            virtio_device->value = value;
            return true;
        }
    }
    return false;    
}

/*!
 * @fn              virtio_cpu_msg_handler
 * @brief           Handles the cpu_msg comming from the backend
 * @note            Executed by the frontend VM, is responsible to write the value into the MMIO register (for the read operation)
 * @param event     Contains the function to be called
 * @param data      Contains the device id
 * @return          void   
 */
static void virtio_cpu_msg_handler(uint32_t event, uint64_t data)
{
    list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
    {
        if(virtio_device->id == data)
        {
            switch(event)
            {
                case VIRTIO_READ_NOTIFY:
                    // write the value into register
                    vcpu_writereg(cpu()->vcpu, virtio_device->reg, virtio_device->value);
                break;
                case VIRTIO_WRITE_NOTIFY:       
                    // TODO: notify vm                           
                break;
            }
            break;
        }
    }
}

/*!
 * @fn              virtio_cpu_send_msg
 * @brief           Sends a message from the backend to the frontend guest (wake up)
 * @note            Executed by the backend VM
 * @param dev_id    Contains the device id
 * @param op        Contains the operation type
 * @return          void
 */
static void virtio_cpu_send_msg(unsigned long dev_id, unsigned long op)
{
    uint64_t data = dev_id;
    struct cpu_msg msg = {VIRTIO_CPUMSG_ID, VIRTIO_WRITE_NOTIFY, data};

    if(op == VIRTIO_READ_OP)
        msg.event = VIRTIO_READ_NOTIFY;
    else if(op == VIRTIO_INTERRUPT_OP) 
        msg.event = VIRTIO_INJECT_INTERRUPT;

    list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
    {
        if(virtio_device->id == dev_id)
        {
            cpu_send_msg(virtio_device->frontend_cpu_id, &msg);
            break;
        }
    }
}

/*!
 * @fn              virtio_inject_interrupt
 * @brief           Injects an interrupt into the vcpu where the backend or frontend VM are running
 * @note            Executed by the backend or frontend VM
 * @param data      Contains the device id
 * @return          void
 */
static void virtio_inject_interrupt(uint64_t data)
{
    for(int i = 0; i < cpu()->vcpu->vm->virtiodevices_num; i++)
        if(cpu()->vcpu->vm->virtiodevices[i].device_id == data)
        {
            vcpu_inject_irq(cpu()->vcpu, cpu()->vcpu->vm->virtiodevices[i].interrupt);
            break;
        }
}

unsigned long virtio_hypercall(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{    
    unsigned long ret = -HC_E_SUCCESS;
    unsigned long dev_id = cpu()->vcpu->regs.x[2];      // device id
    unsigned long reg_off = cpu()->vcpu->regs.x[3];     // MMIO register offset
    unsigned long op = cpu()->vcpu->regs.x[4];          // operation 
    unsigned long value = cpu()->vcpu->regs.x[5];       // register value

    switch(op)
    {
        // write or read operation
        case VIRTIO_WRITE_OP:
        case VIRTIO_READ_OP:
            if(!virtio_hypercall_w_r_operation(dev_id, reg_off, value))
                ret = -HC_E_FAILURE;
            else
                virtio_cpu_send_msg(dev_id, op);
        break;
        // pooling operation
        case VIRTIO_POOLING_OP:
            // As the device ID is unkonwn (hasn't been removed from the list yet), the backend MUST write the value 0 in the first argument
            if(dev_id != 0) 
            {
                ret = -HC_E_FAILURE;
                break;
            }
            else 
            {
                struct virtio_pooling_params *node = NULL;
                node = (struct virtio_pooling_params*)list_pop(&virtio_device_pooling_list);
                if(node == NULL) 
                {
                    ret = -HC_E_FAILURE;
                    break;
                }
                dev_id = node->device_id;
                objpool_free(&virtio_device_pooling_cache, node);
            }
        // ask operation (device id, access address, operation, value to write and access width)
        case VIRTIO_ASK_OP:
            if(reg_off != 0 || value != 0)
                ret = -HC_E_FAILURE;
            else 
            {
                list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
                {
                    if(virtio_device->id == dev_id)
                    {
                        vcpu_writereg(cpu()->vcpu, 1, dev_id);
                        vcpu_writereg(cpu()->vcpu, 2, virtio_device->reg_off);
                        vcpu_writereg(cpu()->vcpu, 3, virtio_device->op);
                        vcpu_writereg(cpu()->vcpu, 4, virtio_device->value);
                        vcpu_writereg(cpu()->vcpu, 5, virtio_device->access_width);
                        return ret;
                    }
                }
                ret = -HC_E_FAILURE;
            }
        break;
        // used event notification
        case VIRTIO_INTERRUPT_OP:
            if(reg_off != 0 || value != 0)
                ret = -HC_E_FAILURE;
            else
                virtio_cpu_send_msg(dev_id, op);
        break;
        default:
            ret = -HC_E_INVAL_ARGS;
        break;
    } 
    
    return ret;
}

/*!
 * @fn              virtio_notify_backend_handler
 * @brief           Notifies the backend VM by injecting an interrupt into the vcpu where the backend VM is running
 * @note            Executed in the backend CPU and only used when the backend execution mode is interrupt
 * @param data      Contains the device id
 * @return          void     
 */
static void virtio_notify_backend_handler(uint64_t data)
{
    irqid_t irq_id = 0;
    for(int i = 0; i < cpu()->vcpu->vm->virtiodevices_num; i++)
        if(cpu()->vcpu->vm->virtiodevices[i].device_id == data)
        {
            // get the interrupt id
            irq_id = cpu()->vcpu->vm->virtiodevices[data].interrupt;
            break;
        }
    // inject the interrupt into the vcpu where the backend VM is running
    if(irq_id)  
        vcpu_inject_irq(cpu()->vcpu, irq_id);
}

/*!
 * @fn              virtio_insert_to_pooling_queue
 * @brief           Notifies the backend VM by inserting the device id into the pooling queue
 * @note            Executed in the backend CPU and only used when the backend execution mode is pooling. In this particular case,
 *                  the backend VM will have to make requests on a periodic form, through hypercalls
 * @param data      Contains the device id
 * @return          void     
 */
static void virtio_insert_to_pooling_queue(uint64_t data)
{
    struct virtio_pooling_params *node = objpool_alloc(&virtio_device_pooling_cache);
    node->device_id = data;
    list_push(&virtio_device_pooling_list, (node_t*)node);
}

bool virtio_mmio_emul_handler(struct emul_access *acc)
{
    struct vm* vm = cpu()->vcpu->vm;
    struct virtio_device virtio_dev; 
    int i;
    // checks if the address that was accessed actually belongs to a VirtIO device
    for(i = 0; i < vm->virtiodevices_num; i++)
    {      
        virtio_dev = vm->virtiodevices[i];
        if (acc->addr >= virtio_dev.va && acc->addr <= virtio_dev.va + virtio_dev.size)         
            break;    
    }
    // can't find a device, wrong address 
    if (i == vm->virtiodevices_num)
        return false;

    list_foreach(virtio_device_list, struct virtio_device_params, virtio_device)
    {
        if(virtio_device->id == virtio_dev.device_id) 
        { 
            struct cpu_msg msg = {VIRTIO_CPUMSG_ID, VIRTIO_NOTIFY_BACKEND_INT, virtio_dev.device_id};         
            virtio_device->frontend_cpu_id = cpu()->id;
            virtio_device->reg_off = acc->addr - virtio_dev.va;
            virtio_device->reg = acc->reg;
            virtio_device->access_width = acc->width;

            // if the frontend driver is writing into the register, then the backend driver must read the value to effectively write it
            if(acc->write)
            {
                int value = vcpu_readreg(cpu()->vcpu, acc->reg);
                virtio_device->op = VIRTIO_WRITE_OP;    
                virtio_device->value = value;
            }
            // if the frontend driver is reading from the register, then the backend driver must write the value into the register
            else
            {
                virtio_device->op = VIRTIO_READ_OP;
                virtio_device->value = 0;                   
            }
            for(int j = 0; j < config.vmlist[virtio_dev.backend_id].platform.virtiodevices_num; j++)
                if(config.vmlist[virtio_dev.backend_id].platform.virtiodevices[j].device_id == virtio_dev.device_id)
                {
                    if(config.vmlist[virtio_dev.backend_id].platform.virtiodevices[j].pooling)
                    {
                        msg.event = VIRTIO_NOTIFY_BACKEND_POOL;
                    }    
                    cpu_send_msg(virtio_device->backend_cpu_id, &msg);

                    // FIXME:
                    cpu()->vcpu->regs.elr_el2 += 4;
                    // Frontend CPU shold be pu in the idle state while the device is being emulated
                    cpu_idle();
                    return true;
                }
            break;   
        }
    }
    return false;
}

/*!
 * @fn              virtio_handler
 * @brief           Handles the cpu_msg comming from the frontend
 * @note            This function is called by the cpu_msg handler and executed in the backend CPU
 * @param event     Contains the function to be called
 * @param data      Contains the device id
 * @return          void     
 */
static void virtio_handler(uint32_t event, uint64_t data)
{
    switch(event){
        case VIRTIO_NOTIFY_BACKEND_INT: 
            virtio_notify_backend_handler(data);
        break;
        case VIRTIO_NOTIFY_BACKEND_POOL:
            virtio_insert_to_pooling_queue(data);
        break;
        case VIRTIO_READ_NOTIFY:
        case VIRTIO_WRITE_NOTIFY: 
            virtio_cpu_msg_handler(event, data);
        break;
        case VIRTIO_INJECT_INTERRUPT:
            virtio_inject_interrupt(data);
        break;
    }
}