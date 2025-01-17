/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2023 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */
#include <pongo.h>

static bool t7000_probe(struct hal_platform_driver* device_driver, struct hal_platform* device) {
    if (device->cpid == 0x7000) {
        return true;
    }
    return false;
}

static struct usb_regs t7000_usb_regs = {
    .reg1 = 0x0e020248,
    .reg2 = 0x0e020250,
    .reg3 = 0x0e020288,
    .otg_irq = 182
};

static bool t7000_get_platform_value(const char* name, void* value, size_t* size) {
    if (strcmp(name, "usb_regs") == 0 && *size == sizeof(struct usb_regs)) {
        memcpy(value, &t7000_usb_regs, sizeof(struct usb_regs));
        return true;
    }
    return false;
}

static struct hal_platform_driver t7000_plat = {
    .name = "Apple A8 (T7000)",
    .context = NULL,
    .probe = t7000_probe,
    .get_platform_value = t7000_get_platform_value
};

static void t7000_init(struct driver* driver) {
    hal_register_platform_driver(&t7000_plat);
}

REGISTER_DRIVER(t7000, t7000_init, NULL, DRIVER_FLAGS_PLATFORM);
