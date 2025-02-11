/*
 * vdisk.c - Пример драйвера виртуального блочного устройства с поддержкой
 * сохранения/восстановления образа для ядра 6.1.0-31-amd64.
 *
 * Для сборки:
 *   - Сохраните этот код в файл vdisk.c.
 *   - Создайте рядом Makefile со следующим содержимым:
 *
 *       obj-m += vdisk.o
 *       all:
 *           make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 *       clean:
 *           make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
 *
 * Замечание:
 *   В ядре 6.1.0-31 вместо функции blk_mq_free_queue используем blk_cleanup_queue,
 *   а alloc_disk_node заменяем на alloc_disk.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/fs.h>

/* Параметры виртуального диска */
#define VDISK_MINOR_CNT      16
#define VDISK_SECTOR_SIZE    512
#define VDISK_SIZE           (16 * 1024 * 1024)  /* 16 МБ */

/* Определение IOCTL-команд */
#define VDISK_IOCTL_MAGIC       'V'
#define VDISK_IOCTL_SAVE_IMAGE  _IOW(VDISK_IOCTL_MAGIC, 0, char*)
#define VDISK_IOCTL_LOAD_IMAGE  _IOW(VDISK_IOCTL_MAGIC, 1, char*)

/* Структура устройства */
struct vdisk_dev {
    unsigned int size;           /* Размер в байтах */
    u8 *data;                    /* Буфер, имитирующий содержимое диска */
    spinlock_t lock;             /* Для синхронизации */
    struct gendisk *gd;          /* Структура описания блочного устройства */
    struct request_queue *queue; /* Очередь запросов через blk-mq */
};

static int major_num = 0;
static struct vdisk_dev *device = NULL;

/* Глобальный tag_set для blk-mq */
static struct blk_mq_tag_set vdisk_tag_set;

/* Если функция blk_mq_rq_to_disk отсутствует, определяем её самостоятельно */
#ifndef blk_mq_rq_to_disk
static inline struct gendisk *blk_mq_rq_to_disk(struct request *rq)
{
    return rq->q->disk;
}
#endif

/*
 * Функция-обработчик запросов (blk-mq)
 */
static blk_status_t vdisk_mq_request(struct blk_mq_hw_ctx *hctx,
                                     const struct blk_mq_queue_data *bd)
{
    struct request *req = bd->rq;
    struct gendisk *gd = blk_mq_rq_to_disk(req);
    struct vdisk_dev *dev = gd->private_data;
    blk_status_t status = BLK_STS_OK;
    unsigned long offset = blk_rq_pos(req) * VDISK_SECTOR_SIZE;
    int dir = rq_data_dir(req);

    if (offset + blk_rq_cur_bytes(req) > dev->size) {
        pr_err("vdisk: Запрос за пределами устройства. offset=%lu, size=%u\n",
               offset, dev->size);
        blk_mq_end_request(req, BLK_STS_IOERR);
        return BLK_STS_IOERR;
    }

    {
        struct bio_vec bvec;
        struct req_iterator iter;
        rq_for_each_segment(bvec, req, iter) {
            void *iovec_mem = kmap_atomic(bvec.bv_page);
            if (dir == READ)
                memcpy(iovec_mem + bvec.bv_offset, dev->data + offset, bvec.bv_len);
            else
                memcpy(dev->data + offset, iovec_mem + bvec.bv_offset, bvec.bv_len);
            offset += bvec.bv_len;
            kunmap_atomic(iovec_mem);
        }
    }

    blk_mq_end_request(req, status);
    return status;
}

/* Операции для blk-mq */
static struct blk_mq_ops vdisk_mq_ops = {
    .queue_rq = vdisk_mq_request,
};

/* Операции блочного устройства */
static int vdisk_open(struct block_device *bdev, fmode_t mode)
{
    return 0;
}

static void vdisk_release(struct gendisk *gd, fmode_t mode)
{
    /* Дополнительных действий не требуется */
}

/*
 * IOCTL-обработчик для операций сохранения/восстановления образа
 */
static int vdisk_ioctl(struct block_device *bdev, fmode_t mode,
                       unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    struct vdisk_dev *dev = bdev->bd_disk->private_data;
    struct file *filp_image;
    loff_t pos;
    char *filename = NULL;
    ssize_t err;

    switch (cmd) {
    case VDISK_IOCTL_SAVE_IMAGE:
        filename = kmalloc(256, GFP_KERNEL);
        if (!filename)
            return -ENOMEM;
        if (copy_from_user(filename, (char __user *)arg, 255)) {
            kfree(filename);
            return -EFAULT;
        }
        filename[255] = '\0';
        pr_info("vdisk: Сохранение образа в файл: %s\n", filename);

        filp_image = filp_open(filename, O_WRONLY | O_CREAT, 0644);
        if (IS_ERR(filp_image)) {
            ret = PTR_ERR(filp_image);
            kfree(filename);
            return ret;
        }
        pos = 0;
        err = kernel_write(filp_image, dev->data, dev->size, &pos);
        filp_close(filp_image, NULL);
        if (err < 0) {
            kfree(filename);
            return err;
        }
        kfree(filename);
        break;

    case VDISK_IOCTL_LOAD_IMAGE:
        filename = kmalloc(256, GFP_KERNEL);
        if (!filename)
            return -ENOMEM;
        if (copy_from_user(filename, (char __user *)arg, 255)) {
            kfree(filename);
            return -EFAULT;
        }
        filename[255] = '\0';
        pr_info("vdisk: Восстановление образа из файла: %s\n", filename);

        filp_image = filp_open(filename, O_RDONLY, 0);
        if (IS_ERR(filp_image)) {
            ret = PTR_ERR(filp_image);
            kfree(filename);
            return ret;
        }
        pos = 0;
        err = kernel_read(filp_image, dev->data, dev->size, &pos);
        filp_close(filp_image, NULL);
        if (err < 0) {
            kfree(filename);
            return err;
        }
        kfree(filename);
        break;

    default:
        return -ENOTTY;
    }

    return 0;
}

static struct block_device_operations vdisk_fops = {
    .owner   = THIS_MODULE,
    .open    = vdisk_open,
    .release = vdisk_release,
    .ioctl   = vdisk_ioctl,
};

/*
 * Инициализация драйвера
 */
static int __init vdisk_init(void)
{
    int ret;

    device = kmalloc(sizeof(struct vdisk_dev), GFP_KERNEL);
    if (!device)
        return -ENOMEM;
    memset(device, 0, sizeof(struct vdisk_dev));
    device->size = VDISK_SIZE;
    spin_lock_init(&device->lock);

    device->data = vmalloc(device->size);
    if (!device->data) {
        kfree(device);
        return -ENOMEM;
    }
    memset(device->data, 0, device->size);

    memset(&vdisk_tag_set, 0, sizeof(vdisk_tag_set));
    vdisk_tag_set.ops = &vdisk_mq_ops;
    vdisk_tag_set.nr_hw_queues = 1;
    vdisk_tag_set.queue_depth = 128;
    vdisk_tag_set.numa_node = NUMA_NO_NODE;
    vdisk_tag_set.cmd_size = 0;
    vdisk_tag_set.flags = 0;

    ret = blk_mq_alloc_tag_set(&vdisk_tag_set);
    if (ret) {
        vfree(device->data);
        kfree(device);
        return ret;
    }

    device->queue = blk_mq_init_queue(&vdisk_tag_set);
    if (IS_ERR(device->queue)) {
        ret = PTR_ERR(device->queue);
        blk_mq_free_tag_set(&vdisk_tag_set);
        vfree(device->data);
        kfree(device);
        return ret;
    }
    device->queue->queuedata = device;

    major_num = register_blkdev(0, "vdisk");
    if (major_num <= 0) {
        /* Для ядра 6.1 используем blk_cleanup_queue */
        blk_cleanup_queue(device->queue);
        blk_mq_free_tag_set(&vdisk_tag_set);
        vfree(device->data);
        kfree(device);
        return -EBUSY;
    }

    /* Для ядра 6.1 используем alloc_disk(), так как alloc_disk_node отсутствует */
    device->gd = alloc_disk(VDISK_MINOR_CNT);
    if (!device->gd) {
        unregister_blkdev(major_num, "vdisk");
        blk_cleanup_queue(device->queue);
        blk_mq_free_tag_set(&vdisk_tag_set);
        vfree(device->data);
        kfree(device);
        return -ENOMEM;
    }

    device->gd->major = major_num;
    device->gd->first_minor = 0;
    device->gd->fops = &vdisk_fops;
    device->gd->private_data = device;
    snprintf(device->gd->disk_name, 32, "vdisk0");
    set_capacity(device->gd, device->size / VDISK_SECTOR_SIZE);
    device->gd->queue = device->queue;

    (void)add_disk(device->gd);

    pr_info("vdisk: Драйвер загружен. major = %d, размер = %u байт\n",
            major_num, device->size);
    return 0;
}

/*
 * Выгрузка драйвера
 */
static void __exit vdisk_exit(void)
{
    del_gendisk(device->gd);
    put_disk(device->gd);
    unregister_blkdev(major_num, "vdisk");
    /* Для очередей, созданных через blk_mq_init_queue, используем blk_cleanup_queue */
    blk_cleanup_queue(device->queue);
    blk_mq_free_tag_set(&vdisk_tag_set);
    vfree(device->data);
    kfree(device);
    pr_info("vdisk: Драйвер выгружен\n");
}

module_init(vdisk_init);
module_exit(vdisk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Neverov Zakhar");
MODULE_DESCRIPTION("Виртуальный диск с сохранением/восстановлением образа для ядра 6.1.0-31-amd64");
