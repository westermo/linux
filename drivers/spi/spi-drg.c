/*
 * Westermo Dragonite SPI controller
 *
 * Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/io.h>

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi_bitbang.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>

#define DRG_SPI_VERSION 1

typedef struct drg_spi_regs {
	u32 version;
#define DRG_SPI_VERSION_MAJOR(_ver) ((_ver) >> 16)

	u32 flags;
#define DRG_SPI_INIT_OK   (1 << 31)
#define DRG_SPI_IRQ       (1 << 4)
#define DRG_SPI_ERROR     (1 << 3)
#define DRG_SPI_LAST      (1 << 2)
#define DRG_SPI_FIRST     (1 << 1)
#define DRG_SPI_OWNER_DRG (1 << 0)

	u32 conf;
	u32 len;

	u32 reserved[60];

	/* offset 0x100 */
#define DRG_SPI_BLOCK_SZ 0x1000
	u16 txdata[DRG_SPI_BLOCK_SZ >> 1];
	u16 rxdata[DRG_SPI_BLOCK_SZ >> 1];
} __packed drg_spi_regs_t;


struct drg_spi {
	struct spi_bitbang bitbang;
	u32 __iomem *poe_ctrl;
	drg_spi_regs_t __iomem *regs;
	struct clk *clk;

	struct completion xfer_done;
	int irq;
	int cs;
};

#define dspi_from_spi(_spi) container_of((_spi)->master, struct drg_spi, master)

static irqreturn_t drg_spi_irq(int irq, void *_dspi)
{
	struct drg_spi *dspi = _dspi;

	/* ack interrupt */
	writel(readl(&dspi->regs->flags) & ~DRG_SPI_IRQ, &dspi->regs->flags);

	complete(&dspi->xfer_done);
	return IRQ_HANDLED;
}

static int drg_spi_set_speed(struct drg_spi *dspi, u32 speed)
{
	u32 pscl, conf;

	/* standard prescaler values: 1,2,4,6,...,30 */
	pscl = DIV_ROUND_UP(clk_get_rate(dspi->clk), speed);
	pscl = roundup(pscl, 2);

	if (pscl > 30)
		return -EINVAL;

	conf  = readl(&dspi->regs->conf) & ~0x1f;
	conf |= BIT(4) | (pscl >> 1);
	writel(conf, &dspi->regs->conf);
	return 0;
}

static inline int drg_spi_wait(struct drg_spi *dspi, int uses_irq)
{
	/* timeout after a total of 500ms has passed */
	unsigned long timeout = msecs_to_jiffies(500);
	int ret;

	/* not all commands use irq signaling, e.g. chipselect options */
	if (uses_irq) {
		ret = wait_for_completion_timeout(&dspi->xfer_done,
								timeout);
		if (ret <= 0)
			return ret ? : -ETIMEDOUT;

		timeout = ret;
	}

	timeout += jiffies;

	do {
		if (!(readl(&dspi->regs->flags) & DRG_SPI_OWNER_DRG))
			return 0;

	} while (time_before(jiffies, timeout));

	return -ETIMEDOUT;
}

static int drg_spi_command(struct drg_spi *dspi, u32 flags,
			   struct spi_transfer *t)
{
	int err;

	if (t && t->speed_hz) {
		err = drg_spi_set_speed(dspi, t->speed_hz);
		if (err)
			return err;
	}

	if (t) {
		writel(t->len, &dspi->regs->len);
		if (t->tx_buf)
			memcpy_toio(&dspi->regs->txdata, t->tx_buf, t->len);
		else
			memset_io(&dspi->regs->txdata, 0, t->len);
	} else {
		writel(0, &dspi->regs->len);
	}

	writel(DRG_SPI_OWNER_DRG | flags, &dspi->regs->flags);

	err = drg_spi_wait(dspi, flags & DRG_SPI_IRQ);
	if (err)
		return err;

	if (readl(&dspi->regs->flags) & DRG_SPI_ERROR)
		return -EIO;

	if (t && t->rx_buf)
		memcpy_fromio(t->rx_buf, &dspi->regs->rxdata, t->len);

	return t ? t->len : 0;
}

static int drg_spi_txrx_bufs(struct spi_device *sdev, struct spi_transfer *t)
{
	struct drg_spi *dspi = spi_master_get_devdata(sdev->master);

	return drg_spi_command(dspi, t->len > 6 ? DRG_SPI_IRQ : 0, t);
}


static void drg_spi_chipselect(struct spi_device *sdev, int active)
{
	struct drg_spi *dspi = spi_master_get_devdata(sdev->master);

	gpio_set_value(dspi->cs, !active);
	drg_spi_command(dspi, active ? DRG_SPI_FIRST : DRG_SPI_LAST, NULL);
}

static size_t drg_spi_max_transfer_size(struct spi_device *spi)
{
	return DRG_SPI_BLOCK_SZ;
}

static int drg_spi_probe (struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct spi_master *master;
	struct drg_spi *dspi;
	struct resource *res;
	int err;

	master = spi_alloc_master(&pdev->dev, sizeof(*dspi));
	if (!master)
		return -ENOMEM;

	dspi = spi_master_get_devdata(master);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	dspi->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(dspi->regs)) {
		err = PTR_ERR(dspi->regs);
		goto err;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	dspi->poe_ctrl = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(dspi->poe_ctrl)) {
		err = PTR_ERR(dspi->poe_ctrl);
		goto err;
	}

	/* Enables the PoE subsystem, PBL should have taken care of
	 * this, but in case it hasn't (e.g. during development) the
	 * system will HARD lock on any register access. */
	writel(readl(dspi->poe_ctrl) | BIT(0), dspi->poe_ctrl);

	if (DRG_SPI_VERSION_MAJOR(readl(&dspi->regs->version)) !=
	    DRG_SPI_VERSION) {
		err = -EINVAL;
		dev_err(&pdev->dev, "error: wrong dragonite firmware version "
			"%#x, expected major version %d\n",
			readl(&dspi->regs->version), DRG_SPI_VERSION);

		goto err;
	}

	dspi->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(dspi->clk)) {
		err = PTR_ERR(dspi->clk);
		goto err;
	}

	init_completion(&dspi->xfer_done);
	dspi->irq = of_irq_get(np, 0);
	if (dspi->irq <= 0) {
		err = dspi->irq ? : -EINVAL;
		goto err;
	}

	err = devm_request_irq(&pdev->dev, dspi->irq, drg_spi_irq, 0,
			       dev_name(&pdev->dev), dspi);
	if (err)
		goto err;

	dspi->cs = of_get_named_gpio(np, "gpios", 0);
	if (dspi->cs < 0) {
		err = dspi->cs ? : -EINVAL;
		goto err;
	}

	master->bus_num = -1;
	master->num_chipselect = 1;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->dev.parent = &pdev->dev;
	master->dev.of_node = np;
	master->max_transfer_size = drg_spi_max_transfer_size;

	dspi->bitbang.master = master;
	dspi->bitbang.chipselect = drg_spi_chipselect;
	dspi->bitbang.txrx_bufs = drg_spi_txrx_bufs;
	err = spi_bitbang_start(&dspi->bitbang);
	if (err)
		goto err;

	gpio_direction_output(dspi->cs, 1);
	gpio_set_value(dspi->cs, 1);

	platform_set_drvdata(pdev, dspi);
	dev_info(&pdev->dev, "ok\n");
	return 0;

err:
	spi_master_put(master);
	return err;
};

static int drg_spi_remove (struct platform_device *pdev)
{
	struct drg_spi *dspi = platform_get_drvdata(pdev);

	spi_bitbang_stop(&dspi->bitbang);
	spi_master_put(dspi->bitbang.master);
	return 0;
};

static const struct of_device_id drg_spi_match[] = {
	{ .compatible = "wmo,drg-spi" },
	{}
};

MODULE_DEVICE_TABLE(of, drg_spi_match);

static struct platform_driver drg_spi_driver = {
	.driver = {
		.name = "drg-spi",
		.of_match_table = drg_spi_match,
	},
	.probe = drg_spi_probe,
	.remove = drg_spi_remove,
};

module_platform_driver(drg_spi_driver);
