/*
 * vdisk.c - Драйвер виртуального диска с возможностью сохранения и восстановления образа
 *
 * Этот модуль реализует виртуальное блочное устройство, данные которого хранятся в памяти.
 * Предусмотрены две команды ioctl для сохранения образа диска в файл и восстановления из файла.
 *
 * Требования:
 *   - Ядро: 4.9.0-13-amd64
 *   - Компиляция: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Пример использования:
 *   1. Соберите модуль и загрузите его (insmod).
 *   2. Устройство появится под именем /dev/vdisk.
 *   3. С помощью пользовательской утилиты (или простого тестового приложения) можно вызвать ioctl:
 *        - VDISK_IOCTL_SAVE    – сохранить образ в файл (по умолчанию /var/vdisk.img)
 *        - VDISK_IOCTL_RESTORE – восстановить образ из файла.
 */

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/vmalloc.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/fcntl.h>

#define VDISK_MAJOR         240
#define VDISK_MINOR_CNT     16
#define VDISK_SECTOR_SIZE   512
#define VDISK_NUM_SECTORS   2048  /* 2048 секторов по 512 байт – около 1 МБ */

/* Путь к файлу для сохранения/восстановления образа можно задать как параметр модуля */
static char *vdisk_image = "/var/vdisk.img";
module_param(vdisk_image, charp, 0644);
MODULE_PARM_DESC(vdisk_image, "Путь к файлу для сохранения/восстановления образа виртуального диска");

#define VDISK_IOCTL_MAGIC   'v'
#define VDISK_IOCTL_SAVE    _IO(VDISK_IOCTL_MAGIC, 1)
#define VDISK_IOCTL_RESTORE _IO(VDISK_IOCTL_MAGIC, 2)

/* Структура, описывающая устройство */
struct vdisk_dev {
    int size;          /* Размер устройства в байтах */
    u8 *data;          /* Указатель на область памяти, где хранятся данные */
    spinlock_t lock;   /* Мьютекс для синхронизации */
    struct request_queue *queue;
    struct gendisk *gd;
};

static struct vdisk_dev *vdisk_device = NULL;

/* Функции для работы с устройством (open/release) */
static int vdisk_open(struct block_device *bdev, fmode_t mode)
{
    return 0;
}

static void vdisk_release(struct gendisk *gd, fmode_t mode)
{
}

/* Функция для получения «геометрии» устройства – нужна некоторым пользовательским утилитам */
static int vdisk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
    geo->heads = 4;
    geo->sectors = 16;
    geo->cylinders = vdisk_device->size / (4 * 16 * VDISK_SECTOR_SIZE);
    geo->start = 0;
    return 0;
}

/* Обработка ioctl-запросов: сохранение и восстановление образа */
static int vdisk_ioctl(struct block_device *bdev, fmode_t mode,
                       unsigned int cmd, unsigned long arg)
{
    struct vdisk_dev *dev = vdisk_device; /* Для простоты рассматриваем только одно устройство */
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;

    switch (cmd) {
    case VDISK_IOCTL_SAVE:
        filp = filp_open(vdisk_image, O_WRONLY | O_CREAT, 0644);
        if (IS_ERR(filp))
            return PTR_ERR(filp);
        ret = kernel_write(filp, dev->data, dev->size, pos);
        filp_close(filp, NULL);
        if (ret < 0)
            return ret;
        printk(KERN_INFO "vdisk: Образ сохранён в %s\n", vdisk_image);
        break;
    case VDISK_IOCTL_RESTORE:
        filp = filp_open(vdisk_image, O_RDONLY, 0);
        if (IS_ERR(filp))
            return PTR_ERR(filp);
        ret = kernel_read(filp, pos, dev->data, dev->size);
        filp_close(filp, NULL);
        if (ret < 0)
            return ret;
        printk(KERN_INFO "vdisk: Образ восстановлен из %s\n", vdisk_image);
        break;
    default:
        return -ENOTTY;
    }
    return 0;
}

static const struct block_device_operations vdisk_fops = {
    .owner = THIS_MODULE,
    .open = vdisk_open,
    .release = vdisk_release,
    .ioctl = vdisk_ioctl,  /* Используем legacy-ioctl */
    .getgeo = vdisk_getgeo,
};

/*
 * Функция обработки запросов legacy-интерфейса.
 * Вызывается для каждого запроса, полученного через очередь.
 */
static void vdisk_request(struct request_queue *q)
{
    struct request *req;
    while ((req = blk_fetch_request(q)) != NULL) {
        struct vdisk_dev *dev = req->rq_disk->private_data;
        sector_t sector = blk_rq_pos(req);
        unsigned int offset = 0;
        unsigned int nbytes;
        int ret = 0;
        struct bio_vec bv;
        struct req_iterator iter;
        
        if (blk_rq_is_passthrough(req)) {
            __blk_end_request_all(req, -EIO);
            continue;
        }

        rq_for_each_segment(bv, req, iter) {
            nbytes = bv.bv_len;
            {
                unsigned long dev_offset = (sector * VDISK_SECTOR_SIZE) + offset;
                if ((dev_offset + nbytes) > dev->size) {
                    ret = -EIO;
                    break;
                }
                if (rq_data_dir(req) == WRITE)
                    memcpy(dev->data + dev_offset, page_address(bv.bv_page) + bv.bv_offset, nbytes);
                else
                    memcpy(page_address(bv.bv_page) + bv.bv_offset, dev->data + dev_offset, nbytes);
            }
            offset += nbytes;
        }
        __blk_end_request_all(req, ret);
    }
}

/* Инициализация модуля */
static int __init vdisk_init(void)
{
    int ret;

    vdisk_device = kzalloc(sizeof(struct vdisk_dev), GFP_KERNEL);
    if (!vdisk_device)
        return -ENOMEM;

    vdisk_device->size = VDISK_NUM_SECTORS * VDISK_SECTOR_SIZE;
    vdisk_device->data = vmalloc(vdisk_device->size);
    if (!vdisk_device->data) {
        kfree(vdisk_device);
        return -ENOMEM;
    }
    spin_lock_init(&vdisk_device->lock);

    ret = register_blkdev(VDISK_MAJOR, "vdisk");
    if (ret < 0) {
        printk(KERN_ERR "vdisk: Не удалось получить major number\n");
        vfree(vdisk_device->data);
        kfree(vdisk_device);
        return ret;
    }

    /* Инициализируем очередь запросов legacy-интерфейсом */
    vdisk_device->queue = blk_init_queue(vdisk_request, &vdisk_device->lock);
    if (!vdisk_device->queue) {
        unregister_blkdev(VDISK_MAJOR, "vdisk");
        vfree(vdisk_device->data);
        kfree(vdisk_device);
        return -ENOMEM;
    }
    vdisk_device->queue->queuedata = vdisk_device;

    vdisk_device->gd = alloc_disk(VDISK_MINOR_CNT);
    if (!vdisk_device->gd) {
        blk_cleanup_queue(vdisk_device->queue);
        unregister_blkdev(VDISK_MAJOR, "vdisk");
        vfree(vdisk_device->data);
        kfree(vdisk_device);
        return -ENOMEM;
    }
    vdisk_device->gd->major = VDISK_MAJOR;
    vdisk_device->gd->first_minor = 0;
    vdisk_device->gd->fops = &vdisk_fops;
    vdisk_device->gd->private_data = vdisk_device;
    snprintf(vdisk_device->gd->disk_name, 32, "vdisk");
    set_capacity(vdisk_device->gd, VDISK_NUM_SECTORS);
    vdisk_device->gd->queue = vdisk_device->queue;

    add_disk(vdisk_device->gd);
    printk(KERN_INFO "vdisk: Модуль загружен. Размер диска: %d байт.\n", vdisk_device->size);
    return 0;
}

static void __exit vdisk_exit(void)
{
    del_gendisk(vdisk_device->gd);
    put_disk(vdisk_device->gd);
    blk_cleanup_queue(vdisk_device->queue);
    unregister_blkdev(VDISK_MAJOR, "vdisk");
    vfree(vdisk_device->data);
    kfree(vdisk_device);
    printk(KERN_INFO "vdisk: Модуль выгружен.\n");
}

module_init(vdisk_init);
module_exit(vdisk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Neverov Zakhar");
MODULE_DESCRIPTION("Драйвер виртуального диска с сохранением и восстановлением образа");

