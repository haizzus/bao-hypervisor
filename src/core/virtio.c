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

/*!
 * @struct  virtio_devices_list
 * @brief   Contains list of all VirtIO devices       
 */
struct list virtio_devices_list;

OBJPOOL_ALLOC(virtio_frontend_access_pool, struct virtio_access, sizeof(struct virtio_access));
OBJPOOL_ALLOC(virtio_backend_access_pool, struct virtio_access, sizeof(struct virtio_access));
OBJPOOL_ALLOC(virtio_devices_pool, struct virtio_devices, sizeof(struct virtio_devices));

// functions prototypes
static void virtio_handler(uint32_t, uint64_t);
static int virtio_prio_node_cmp(node_t* _n1, node_t* _n2);

// create the handler for the cpu_msg
CPU_MSG_HANDLER(virtio_handler, VIRTIO_CPUMSG_ID);

void virtio_init()
{
    int driver_id = 0;
    volatile int i, vm_id;
    int backend_devices[VIRTIO_DEVICES_NUM];

    objpool_init(&virtio_devices_pool);
    objpool_init(&virtio_frontend_access_pool);
    objpool_init(&virtio_backend_access_pool);
    list_init(&virtio_devices_list);

    // initialize the array to verify if there is only one backend for each virtio device
    for (i = 0; i < VIRTIO_DEVICES_NUM; i++)
        backend_devices[i] = -1;

    // create the list of all virtio devices available and assign the backend and frontend ids
    for (vm_id = 0; vm_id < config.vmlist_size; vm_id++)
    {
        struct vm_config *vm_config = &config.vmlist[vm_id]; 
        for (i = 0; i < vm_config->platform.virtiodevices_num; i++) 
        {
            struct virtio_device *dev = &vm_config->platform.virtiodevices[i];
            if (dev->is_back_end)
            {
                struct virtio_devices *node = objpool_alloc(&virtio_devices_pool);
                node->device_id = dev->device_id;
                list_push(&virtio_devices_list, (node_t*)node);

                // more than one backend for the same virtio device
                if (backend_devices[dev->device_id] != -1) 
                {
                    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
                    {
                        objpool_free(&virtio_devices_pool, (struct virtio_devices*)list_pop(&virtio_devices_list));
                    }
                    ERROR("Failed to link backend to the device, more than one back-end was atributed to the VirtIO device %d", dev->device_id);
                }
                // first backend for the virtio device
                else 
                {
                    dev->backend_vm_id = vm_id;
                    backend_devices[dev->device_id] = vm_id;
                }
            }
            else 
            {
                dev->frontend_vm_id = vm_id;
                dev->frontend_id = driver_id++;
            }
        }
    }
}

void virtio_assign_backend_cpu(struct vm* vm)
{
    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
    {
        if (vm->virtiodevices[virtio_device->device_id].backend_vm_id == cpu()->vcpu->vm->id)
            virtio_device->backend_cpu_id = cpu()->id;
    }
}

/*!
 * @fn                  virtio_hypercall_w_r_operation
 * @brief               Performs a write or read operation in a VirtIO device
 * @note                Executed by the backend VM
 * @param dev_id        Contains the device id
 * @param reg_off       Contains the MMIO register offset
 * @param value         Contains the register value
 * @param frontend_id   Contains the frontend driver id
 * @return              true if the operation was successful, false otherwise     
 */
static bool virtio_hypercall_w_r_operation(unsigned long dev_id, unsigned long reg_off, unsigned long value)
{
    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
    {
        if(virtio_device->device_id == dev_id)
        {
            // pop the first element of the backend list (most prioritary request)
            struct virtio_access* node = (struct virtio_access*)list_pop(&virtio_device->backend_access_list);
            
            // if the register is wrong returns false
            if(node->reg_off != reg_off)
                break;

            // Update the value
            node->value = value;

            // Update the frontend request list
            struct virtio_access *frontend_node = objpool_alloc(&virtio_frontend_access_pool);
            frontend_node->access_width = node->access_width;
            frontend_node->frontend_cpu_id = node->frontend_cpu_id;
            frontend_node->frontend_vm_id = node->frontend_vm_id;
            frontend_node->op = node->op;
            frontend_node->reg = node->reg;
            frontend_node->reg_off = node->reg_off;
            frontend_node->value = node->value;
            list_push(&virtio_device->frontend_access_list, (node_t*)frontend_node);

            // free the backend node
            objpool_free(&virtio_backend_access_pool, node);

            // return
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
    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
    {
        if(virtio_device->device_id == data)
        {
            // pop the first element of the list (most prioritary request)
            struct virtio_access* node = (struct virtio_access*)list_pop(&virtio_device->frontend_access_list);

            switch(event)
            {
                case VIRTIO_READ_NOTIFY:
                    // write the value into register
                    vcpu_writereg(cpu()->vcpu, node->reg, node->value);
                break;
                case VIRTIO_WRITE_NOTIFY:       
                    // TODO: notify vm                           
                break;
            }
            // free the node
            objpool_free(&virtio_frontend_access_pool, node);
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

    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
    {
        if(virtio_device->device_id == dev_id)
        {
            // get the first element of the list (most prioritary request)
            struct virtio_access* node = (struct virtio_access*)list_peek(&virtio_device->frontend_access_list);

            if (node == NULL)
                ERROR("Failed to get the first element of the list");
            
            // send the message to the frontend guest
            cpu_send_msg(node->frontend_cpu_id, &msg);
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
    volatile int i;
    for(i = 0; i < cpu()->vcpu->vm->virtiodevices_num; i++)
        if(cpu()->vcpu->vm->virtiodevices[i].device_id == data)
        {
            vcpu_inject_irq(cpu()->vcpu, cpu()->vcpu->vm->virtiodevices[i].interrupt);
            break;
        }
}

unsigned long virtio_hypercall(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{    
    unsigned long ret = -HC_E_SUCCESS;
    unsigned long dev_id = cpu()->vcpu->regs.x[2];          // device id
    unsigned long reg_off = cpu()->vcpu->regs.x[3];         // MMIO register offset
    unsigned long op = cpu()->vcpu->regs.x[4];              // operation 
    unsigned long value = cpu()->vcpu->regs.x[5];           // register value

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
        // ask operation
        case VIRTIO_ASK_OP:
            if(reg_off != 0 || value != 0)
            {
                ret = -HC_E_FAILURE;
                break;
            }
            list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
            {
                if(virtio_device->device_id == dev_id)
                {
                    // get the first element of the list (most prioritary request)
                    struct virtio_access* node = (struct virtio_access*)list_peek(&virtio_device->backend_access_list);
                    if(node == NULL) 
                    {
                        ret = -HC_E_FAILURE;
                        break;
                    }                     
                    // write the values into the registers
                    vcpu_writereg(cpu()->vcpu, 1, dev_id);
                    vcpu_writereg(cpu()->vcpu, 2, node->reg_off);
                    vcpu_writereg(cpu()->vcpu, 3, node->op);
                    vcpu_writereg(cpu()->vcpu, 4, node->value);
                    vcpu_writereg(cpu()->vcpu, 5, node->access_width);
                    vcpu_writereg(cpu()->vcpu, 6, node->frontend_id);
                    return ret;
                }
            }
            ret = -HC_E_FAILURE;
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
    volatile int i;
    for(i = 0; i < cpu()->vcpu->vm->virtiodevices_num; i++)
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

bool virtio_mmio_emul_handler(struct emul_access *acc)
{
    struct vm* vm = cpu()->vcpu->vm;
    struct virtio_device virtio_dev; 
    volatile int i, j;

    // find the device that is being accessed
    for(i = 0; i < vm->virtiodevices_num; i++)
    {      
        virtio_dev = vm->virtiodevices[i];
        if (acc->addr >= virtio_dev.va && acc->addr <= virtio_dev.va + virtio_dev.size)         
            break;    
    }
    // can't find a device, wrong address 
    if (i == vm->virtiodevices_num)
       return false;

    list_foreach(virtio_devices_list, struct virtio_devices, virtio_device)
    {
        if(virtio_device->device_id == virtio_dev.device_id) 
        {
            struct virtio_access *node = objpool_alloc(&virtio_backend_access_pool);  
            struct cpu_msg msg = {VIRTIO_CPUMSG_ID, VIRTIO_NOTIFY_BACKEND_INT, virtio_dev.device_id};         
            node->frontend_cpu_id = cpu()->id;
            node->reg_off = acc->addr - virtio_dev.va;
            node->reg = acc->reg;
            node->access_width = acc->width;
            node->frontend_vm_id = vm->virtiodevices[virtio_dev.device_id].frontend_vm_id;
            node->frontend_id = vm->virtiodevices[virtio_dev.device_id].frontend_id;
            node->priority = vm->virtiodevices[virtio_dev.device_id].priority;

            // if the frontend driver is writing into the register, then the backend driver must read the value to effectively write it
            if(acc->write)
            {
                int value = vcpu_readreg(cpu()->vcpu, acc->reg);
                node->op = VIRTIO_WRITE_OP;    
                node->value = value;
            }
            // if the frontend driver is reading from the register, then the backend driver must write the value into the register
            else
            {
                node->op = VIRTIO_READ_OP;
                node->value = 0;                   
            }
            for(j = 0; j < config.vmlist[virtio_dev.backend_vm_id].platform.virtiodevices_num; j++)
            {
                if(config.vmlist[virtio_dev.backend_vm_id].platform.virtiodevices[j].device_id == virtio_dev.device_id)
                {
                    if(config.vmlist[virtio_dev.backend_vm_id].platform.virtiodevices[j].pooling)
                    {
                        msg.event = VIRTIO_NOTIFY_BACKEND_POOL;
                    }

                    // update the backend request list (ordered by priority)
                    list_insert_ordered(&virtio_device->backend_access_list, (node_t*)node, virtio_prio_node_cmp);

                    // send the message to the backend
                    cpu_send_msg(virtio_device->backend_cpu_id, &msg);

                    // increment the program counter
                    cpu()->vcpu->regs.elr_el2 += 4;

                    // Frontend CPU shold be put in the idle state while the device is being emulated
                    cpu_idle();

                    return true;
                }
            }
            break;   
        }
    }
    return false;
}

/*!
 * @fn              virtio_handler
 * @brief           Handles the cpu_msg comming from the frontend or backend
 * @note            This function is called by the cpu_msg handler and executed in the backend or frontend CPU
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
            // Do nothing (the backend will make requests on a periodic form, through hypercalls)
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

/*!
 * @fn              virtio_prio_node_cmp
 * @brief           Compares two virtio devices by priority
 * @note            This function is used to order the virtio devices by priority (higher number means lower priority)
 * @param _n1       Contains the first node
 * @param _n2       Contains the second node
 * @return          int     
 */
static int virtio_prio_node_cmp(node_t* _n1, node_t* _n2)
{
    struct virtio_access *n1 = (struct virtio_access*) _n1;
    struct virtio_access *n2 = (struct virtio_access*) _n2;

    if (n1->priority > n2->priority)
        return 1;
    else if (n1->priority < n2->priority)
        return -1;
    else
        return 0;
}