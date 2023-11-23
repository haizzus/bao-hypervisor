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

#include <virtio.h>
#include <cpu.h>
#include <vm.h>
#include <hypercall.h>
#include <ipc.h>
#include <objpool.h>
#include <config.h>

#define VIRTIO_INSTANCES_NUM 50
#define VIRTIO_UNINITIALIZED -1

/*!
 * @enum
 * @brief   VirtIO hypercall events
 * @note    Used by the backend VM      
 */
enum VIRTIO_HYP_EVENTS {
    VIRTIO_WRITE_OP,        // Write operation
    VIRTIO_READ_OP,         // Read operation 
    VIRTIO_ASK_OP,          // Ask operation (used to get the next request)                  
    VIRTIO_NOTIFY_OP,       // Notification operation (used buffer notification or configuration change notification)
    VIRTIO_VM_CREATE_OP,    // VM create operation
    VIRTIO_VM_DESTROY_OP,   // VM destroy operation
};

/*!
 * @enum
 * @brief   VirtIO cpu_msg events      
 */
enum VIRTIO_CPU_MSG_EVENTS {
    VIRTIO_WRITE_NOTIFY,        // Write notification
    VIRTIO_READ_NOTIFY,         // Read notification
    VIRTIO_INJECT_INTERRUPT,    // Inject interrupt into the frontend VM or backend VM
    VIRTIO_NOTIFY_BACKEND_POOL, // Notify backend by pooling
};

/*!
 * @enum
 * @brief   VirtIO direction      
 */
enum VIRTIO_DIRECTION {
    VIRTIO_FRONTEND_TO_BACKEND,
    VIRTIO_BACKEND_TO_FRONTEND,
};

enum VIRTIO_VM_STATE {
    VIRTIO_VM_UNASSIGNED,
    VIRTIO_VM_ASSIGNED,
};

/*!
 * @struct  virtio_instance
 * @brief   Contains information about a virtio device & driver pair (virtio instance)
 */
struct virtio_instance {
    unsigned int backend_cpu_id;        // CPU ID of the VirtIO backend
    unsigned int backend_vm_id;         // VM ID of the VirtIO backend
    unsigned int backend_id;            // Backend ID of the VirtIO backend
    unsigned int frontend_cpu_id;       // CPU ID of the guest that is accessing the MMIO register
    unsigned int frontend_vm_id;        // VM ID of the guest that is accessing the MMIO register
    unsigned int frontend_id;           // Frontend ID of the driver that is accessing the MMIO register
    unsigned int virtio_interrupt;      // Interrupt used to notify the backend VM that a new VirtIO request is available
    unsigned int device_interrupt;      // Interrupt used to notify the frontend guest (used buffer notification or configuration change notification)
    unsigned int priority;              // Priority (higher number means lower priority) of the driver (Used to schedule the backend driver)
    unsigned int device_type;           // Device type (Used to identify the real physical device) 
    bool pooling;                       // Delineate if the backend execution mode is going to be pooling or by interrupts
};

/*!
 * @struct  virtio_access
 * @brief   Contains the specific parameters of a VirtIO device access
 */
struct virtio_access {
    node_t node;                    // Node of the list
    unsigned long reg_off;          // Gives the offset of the MMIO Register that was accessed
    unsigned long addr;             // Gives the address of the MMIO Register that was accessed
    unsigned long access_width;     // Access width (VirtIO MMIO only allows 4-byte wide and alligned accesses)
    unsigned long op;               // Write or Read operation
    unsigned long value;            // Value to write or read
    unsigned int frontend_id;       // Frontend ID of the driver that is accessing the MMIO register
    unsigned long reg;              // CPU register used to store the MMIO register value
    unsigned int priority;          // Priority (higher number means lower priority) of the driver (Used to schedule the backend driver)
};

/*!
 * @struct  virtio
 * @brief   Contains the necessary information of a VirtIO driver/device (instance)
 */
struct virtio {
    node_t node;                            // Node of the list
    uint64_t virtio_id;                     // VirtIO ID (used to connect each frontend driver to the backend device)
    enum VIRTIO_VM_STATE state;             // State of the VirtIO instance (assigned or unassigned)
    enum VIRTIO_DIRECTION direction;        // Direction of the VirtIO flow
    struct list frontend_access_list;       // List of frontend virtio_access (frontend request list) 
    struct list backend_access_list;        // List of backend virtio_access (backend request list)
    struct list backend_access_ask_list;    // List of backend virtio_access (backend ask list)
    struct virtio_instance instance;        // Virtio instance (driver + device) information
};

/*!
 * @struct  virtio_list
 * @brief   Contains list of all VirtIO instances (Driver + Device)      
 */
struct list virtio_list;

OBJPOOL_ALLOC(virtio_frontend_access_pool, struct virtio_access, sizeof(struct virtio_access));
OBJPOOL_ALLOC(virtio_backend_access_pool, struct virtio_access, sizeof(struct virtio_access));
OBJPOOL_ALLOC(virtio_backend_access_ask_pool, struct virtio_access, sizeof(struct virtio_access));
OBJPOOL_ALLOC(virtio_pool, struct virtio, sizeof(struct virtio));

// functions prototypes
static void virtio_handler(uint32_t, uint64_t);
static int virtio_prio_node_cmp(node_t* _n1, node_t* _n2);

// create the handler for the cpu_msg
CPU_MSG_HANDLER(virtio_handler, VIRTIO_CPUMSG_ID);

void virtio_init()
{
    int frontend_id = 0;
    int backend_id = 0;
    volatile int i, vm_id;
    int backend_devices[VIRTIO_INSTANCES_NUM];

    objpool_init(&virtio_pool);
    objpool_init(&virtio_frontend_access_pool);
    objpool_init(&virtio_backend_access_pool);
    objpool_init(&virtio_backend_access_ask_pool);
    list_init(&virtio_list);

    // initialize the array to verify if there is only one backend for each virtio instance
    for (i = 0; i < VIRTIO_INSTANCES_NUM; i++)
        backend_devices[i] = VIRTIO_UNINITIALIZED;

    // create the list of all virtio instances available and assign the backend and frontend ids
    for (vm_id = 0; vm_id < config.vmlist_size; vm_id++)
    {
        struct vm_config *vm_config = &config.vmlist[vm_id]; 
        for (i = 0; i < vm_config->platform.virtiodevices_num; i++) 
        {
            struct virtio_device *dev = &vm_config->platform.virtiodevices[i];
            if (dev->is_back_end)
            {
                struct virtio *node = objpool_alloc(&virtio_pool);
                node->virtio_id = dev->virtio_id;
                node->state = VIRTIO_VM_UNASSIGNED;
                list_push(&virtio_list, (node_t*)node);

                // more than one backend for the same virtio instance
                if (backend_devices[dev->virtio_id] != VIRTIO_UNINITIALIZED) 
                {
                    list_foreach(virtio_list, struct virtio, virtio_device)
                    {
                        objpool_free(&virtio_pool, (struct virtio*)list_pop(&virtio_list));
                    }
                    ERROR("Failed to link backend to the device, more than one back-end was atributed to the VirtIO instance %d", dev->virtio_id);
                }
                // first backend for the virtio instance
                else 
                {
                    dev->backend_vm_id = vm_id;
                    dev->backend_id = backend_id++;
                    backend_devices[dev->virtio_id] = vm_id;
                }
            }
            else 
            {
                dev->frontend_vm_id = vm_id;
                dev->frontend_id = frontend_id++;
            }
        }
    }

    // checks if there is a 1-to-1 mapping between a virtio backend and virtio frontend
    if (backend_id != frontend_id)
        ERROR("There is no 1-to-1 mapping between a virtio backend and virtio frontend");

    // initialize the virtio instances
    for (vm_id = 0; vm_id < config.vmlist_size; vm_id++)
    {
        struct vm_config *vm_config = &config.vmlist[vm_id]; 
        for (i = 0; i < vm_config->platform.virtiodevices_num; i++) 
        {
            struct virtio_device *dev = &vm_config->platform.virtiodevices[i];
            list_foreach(virtio_list, struct virtio, virtio_device)
            {
                if (dev->virtio_id == virtio_device->virtio_id)
                {
                    if (dev->is_back_end)
                    {
                        virtio_device->instance.backend_vm_id = dev->backend_vm_id;
                        virtio_device->instance.backend_id = dev->backend_id;
                        virtio_device->instance.device_type = dev->device_type;
                        virtio_device->instance.virtio_interrupt = vm_config->platform.virtio_interrupt;
                        virtio_device->instance.pooling = vm_config->platform.virtio_pooling;
                    }
                    else
                    {
                        virtio_device->instance.frontend_vm_id = dev->frontend_vm_id;
                        virtio_device->instance.frontend_id = dev->frontend_id;
                        virtio_device->instance.priority = dev->priority;
                        virtio_device->instance.device_interrupt = dev->device_interrupt;
                    }
                }
            }
        }
    }
}

void virtio_assign_cpus(struct vm* vm)
{
    for (int i = 0; i < vm->virtiodevices_num; i++)
    {
        list_foreach(virtio_list, struct virtio, virtio_device)
        {
            if (vm->virtiodevices[i].virtio_id == virtio_device->virtio_id)
            {
                if (vm->virtiodevices[i].backend_vm_id == cpu()->vcpu->vm->id)
                {
                    virtio_device->instance.backend_cpu_id = cpu()->id;
                    return;
                }
                else if (vm->virtiodevices[i].frontend_vm_id == cpu()->vcpu->vm->id)
                {
                    virtio_device->instance.frontend_cpu_id = cpu()->id;
                    return;
                }
            }
        }
    }
}

/*!
 * @fn                  virtio_hypercall_w_r_operation
 * @brief               Performs a write or read operation in a VirtIO device
 * @note                Executed by the backend VM
 * @param virtio_id     Contains the virtio id
 * @param reg_off       Contains the MMIO register offset
 * @param value         Contains the register value
 * @return              true if the operation was successful, false otherwise     
 */
static bool virtio_hypercall_w_r_operation(unsigned long virtio_id, unsigned long reg_off, unsigned long value)
{
    list_foreach(virtio_list, struct virtio, virtio_device)
    {
        if(virtio_device->virtio_id == virtio_id)
        {
            // pop the first element of the backend list (most prioritary request)
            struct virtio_access* node = (struct virtio_access*)list_pop(&virtio_device->backend_access_list);
            
            // if the register is wrong returns false
            if(node->reg_off != reg_off)
                break;

            // update the value
            node->value = value;

            // update the direction
            virtio_device->direction = VIRTIO_BACKEND_TO_FRONTEND;

            // update the frontend request list
            struct virtio_access *frontend_node = objpool_alloc(&virtio_frontend_access_pool);
            frontend_node->access_width = node->access_width;
            frontend_node->priority = node->priority;
            frontend_node->op = node->op;
            frontend_node->reg = node->reg;
            frontend_node->reg_off = node->reg_off;
            frontend_node->addr = node->addr;
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
 * @param data      Contains the virtio id
 * @return          void   
 */
static void virtio_cpu_msg_handler(uint32_t event, uint64_t data)
{
    list_foreach(virtio_list, struct virtio, virtio_device)
    {
        if(virtio_device->virtio_id == data)
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
            cpu()->vcpu->active = true;
            break;
        }
    }
}

/*!
 * @fn                  virtio_cpu_send_msg
 * @brief               Sends a message from the backend CPU to the frontend CPU (wake up)
 * @note                Executed by the backend CPU
 * @param virtio_id     Contains the virtio id
 * @param op            Contains the operation type
 * @return              void
 */
static void virtio_cpu_send_msg(unsigned long virtio_id, unsigned long op)
{
    struct cpu_msg msg = {VIRTIO_CPUMSG_ID, VIRTIO_WRITE_NOTIFY, (uint64_t)virtio_id};

    if (op == VIRTIO_READ_OP)
        msg.event = VIRTIO_READ_NOTIFY;
    else if (op == VIRTIO_NOTIFY_OP) 
        msg.event = VIRTIO_INJECT_INTERRUPT;
    
    list_foreach(virtio_list, struct virtio, virtio_device)
    {
        if(virtio_device->virtio_id == virtio_id)
        {
            // if the operation is a read or write operation, then the backend must send the message to the frontend guest according to the most prioritary request
            if (op == VIRTIO_READ_OP || op == VIRTIO_WRITE_OP)
            {
                // get the first element of the list (most prioritary request)
                struct virtio_access* node = (struct virtio_access*)list_peek(&virtio_device->frontend_access_list);

                if (node == NULL)
                    ERROR("Failed to get the first element of the list");
            }

            // if the operation is an `VIRTIO_NOTIFY_OP`, then the backend only needs to send a notification to wake up the frontend guest
            
            // send the message to the frontend guest
            cpu_send_msg(virtio_device->instance.frontend_cpu_id, &msg);
        }
    }
}

/*!
 * @fn              virtio_inject_interrupt
 * @brief           Injects an interrupt into the vcpu where the frontend VM or backend VM are running
 * @note            Executed by frontend CPU (Used buffer notification or change configuration notification) or backend CPU (backend interrupt mode)
 * @param data      Contains the virtio id
 * @return          void
 */
static void virtio_inject_interrupt(uint64_t data)
{
    irqid_t irq_id = 0;

    list_foreach(virtio_list, struct virtio, virtio_device)
    {
        if(virtio_device->virtio_id == data)
        {
            // if the direction is from the frontend to the backend, then the interrupt is the virtio interrupt
            // if the direction is from the backend to the frontend, then the interrupt is the device interrupt
            if (virtio_device->direction == VIRTIO_FRONTEND_TO_BACKEND)
                irq_id = virtio_device->instance.virtio_interrupt;
            else
                irq_id = virtio_device->instance.device_interrupt;
            break;
        }
    }

    // inject the interrupt into the vcpu where the frontend VM or backend VM are running, if valid
    if(irq_id)
        vcpu_inject_irq(cpu()->vcpu, irq_id);
    else
        ERROR("Failed to inject interrupt");
}

unsigned long virtio_hypercall(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{    
    unsigned long ret = -HC_E_SUCCESS;                      // return value
    unsigned long virtio_id = cpu()->vcpu->regs.x[2];       // virtio id
    unsigned long reg_off = cpu()->vcpu->regs.x[3];         // MMIO register offset
    //unsigned long addr = cpu()->vcpu->regs.x[4];            // MMIO register address
    unsigned long op = cpu()->vcpu->regs.x[5];              // operation 
    unsigned long value = cpu()->vcpu->regs.x[6];           // register value

    switch(op)
    {
        // write or read operation
        case VIRTIO_WRITE_OP:
        case VIRTIO_READ_OP:
            if(!virtio_hypercall_w_r_operation(virtio_id, reg_off, value))
                ret = -HC_E_FAILURE;
            else
                virtio_cpu_send_msg(virtio_id, op);
        break;
        // ask operation (used to get the next request)
        case VIRTIO_ASK_OP:
            if(reg_off != 0 || value != 0)
            {
                ret = -HC_E_FAILURE;
                break;
            }
            list_foreach(virtio_list, struct virtio, virtio_device)
            {
                // if the virtio device is the same as the one that is being accessed and the backend cpu and vm are the same as the current cpu and vm
                if(virtio_device->virtio_id == virtio_id && 
                   cpu()->id == virtio_device->instance.backend_cpu_id && 
                   cpu()->vcpu->vm->id == virtio_device->instance.backend_vm_id)
                {
                    // get the first element of the ask list (most prioritary request)
                    struct virtio_access* node = (struct virtio_access*)list_pop(&virtio_device->backend_access_ask_list);
                    if(node == NULL) 
                    {
                        ret = -HC_E_FAILURE;
                        break;
                    }
                    // write the values into the registers
                    vcpu_writereg(cpu()->vcpu, 1, virtio_id);
                    vcpu_writereg(cpu()->vcpu, 2, node->reg_off);
                    vcpu_writereg(cpu()->vcpu, 3, node->addr);
                    vcpu_writereg(cpu()->vcpu, 4, node->op);
                    vcpu_writereg(cpu()->vcpu, 5, node->value);
                    vcpu_writereg(cpu()->vcpu, 6, node->access_width);

                    // free the node
                    objpool_free(&virtio_backend_access_ask_pool, node);
                    
                    return ret;
                }
            }
            ret = -HC_E_FAILURE;
        break;
        // used buffer notification or configuration change notification
        case VIRTIO_NOTIFY_OP:
            if(reg_off != 0 || value != 0)
                ret = -HC_E_FAILURE;
            else
                virtio_cpu_send_msg(virtio_id, op);
        break;
        // create or destroy operation
        case VIRTIO_VM_CREATE_OP:
        case VIRTIO_VM_DESTROY_OP:
            list_foreach(virtio_list, struct virtio, virtio_device)
            {
                if(virtio_device->virtio_id == virtio_id && 
                   cpu()->id == virtio_device->instance.backend_cpu_id && 
                   cpu()->vcpu->vm->id == virtio_device->instance.backend_vm_id)
                {
                    if ((op == VIRTIO_VM_CREATE_OP && virtio_device->state == VIRTIO_VM_ASSIGNED) ||
                        (op == VIRTIO_VM_DESTROY_OP && virtio_device->state == VIRTIO_VM_UNASSIGNED))
                        ret = -HC_E_FAILURE;
                    else
                        virtio_device->state = (op == VIRTIO_VM_CREATE_OP) ? VIRTIO_VM_ASSIGNED : VIRTIO_VM_UNASSIGNED;
                    return ret;
                }
            }
            ret = -HC_E_FAILURE;
            break;
        default:
            ret = -HC_E_INVAL_ARGS;
        break;
    }
    return ret;
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

    list_foreach(virtio_list, struct virtio, virtio_device)
    {
        if(virtio_device->virtio_id == virtio_dev.virtio_id) 
        {
            struct virtio_access *node = objpool_alloc(&virtio_backend_access_pool);  
            struct cpu_msg msg = {VIRTIO_CPUMSG_ID, VIRTIO_INJECT_INTERRUPT, virtio_dev.virtio_id};         
            node->reg_off = acc->addr - virtio_dev.va;
            node->addr = acc->addr;
            node->reg = acc->reg;
            node->access_width = acc->width;
            node->priority = virtio_device->instance.priority;
            node->frontend_id = virtio_device->instance.frontend_id;

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
                if(config.vmlist[virtio_dev.backend_vm_id].platform.virtiodevices[j].virtio_id == virtio_dev.virtio_id)
                {
                    if(config.vmlist[virtio_dev.backend_vm_id].platform.virtiodevices[j].pooling)
                    {
                        msg.event = VIRTIO_NOTIFY_BACKEND_POOL;
                    }

                    // update the direction
                    virtio_device->direction = VIRTIO_FRONTEND_TO_BACKEND;

                    // update the backend request list (ordered by priority)
                    list_insert_ordered(&virtio_device->backend_access_list, (node_t*)node, virtio_prio_node_cmp);

                    // update the backend ask list (ordered by priority)
                    struct virtio_access *node_ask = objpool_alloc(&virtio_backend_access_ask_pool);  
                    *node_ask = *node;
                    list_insert_ordered(&virtio_device->backend_access_ask_list, (node_t*)node_ask, virtio_prio_node_cmp);

                    // send the message to the backend
                    cpu_send_msg(virtio_device->instance.backend_cpu_id, &msg);

                    // increment the program counter
                    cpu()->vcpu->regs.elr_el2 += 4;

                    // frontend CPU should be put in the idle state while the device is being emulated
                    cpu()->vcpu->active = false;
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
    switch(event)
    {
        case VIRTIO_INJECT_INTERRUPT:
            virtio_inject_interrupt(data);
        break;
        case VIRTIO_NOTIFY_BACKEND_POOL:
            // Do nothing (the backend VM will make requests on a periodic form, through hypercalls)
        break;
        case VIRTIO_READ_NOTIFY:
        case VIRTIO_WRITE_NOTIFY: 
            virtio_cpu_msg_handler(event, data);
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