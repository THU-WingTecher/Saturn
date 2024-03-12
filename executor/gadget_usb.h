#if SYZ_EXECUTOR || __NR_syz_attach_gadget
#include <linux/usb/ch9.h>
#include <string.h>
// #include <time.h>
#include <unistd.h>
#include <usbg/function/hid.h>
#include <usbg/usbg.h>
// #include <usbg/function/uvc.h>
#include <usbg/function/loopback.h>
#include <usbg/function/midi.h>
#include <usbg/function/ms.h>
#include <usbg/function/net.h>
#include <usbg/function/printer.h>
// #include <usbg/function/uac2.h>

#define MAX_FUNC_NUM 2
#define MAX_DEVICE_NUM 8

// union for function attr
union usbg_function_attr {
	int default_attr;
	struct usbg_f_midi_attrs midi_attr;
	struct usbg_f_ms_attrs ms_attr;
	struct usbg_f_net_attrs net_attr;
	struct usbg_f_printer_attrs printer_attr;
	struct usbg_f_loopback_attrs loopback_attr;
	struct usbg_f_hid_attrs hid_attr;
};

// gadget func struct
struct usbg_func_config {
	usbg_function_type f_type;
	// void* f_attrs;
	union usbg_function_attr f_attrs;
};

struct usb_gadget_device {
	struct usbg_gadget_attrs* g_attrs;
	struct usbg_config_attrs* c_attrs;
	int func_num;
	// array for usbg_func_config
	struct usbg_func_config func_conf[MAX_FUNC_NUM];
};

struct usb_gadget_device usb_device[MAX_DEVICE_NUM];

// identify info, so not generate it
struct usbg_gadget_strs g_strs = {
    .manufacturer = (char*)"Foo Inc.",
    .product = (char*)"Bar Gadget",
    .serial = (char*)"12345678"};

struct usbg_config_strs c_strs = {
    .configuration = (char*)"1xMIDI"};

static int remove_gadget(usbg_gadget* g)
{
	int usbg_ret;
	usbg_udc* u;

	/* Check if gadget is enabled */
	u = usbg_get_gadget_udc(g);

	/* If gadget is enable we have to disable it first */
	if (u) {
		usbg_ret = usbg_disable_gadget(g);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error on disable gadget udc\n");
			fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
				usbg_strerror((usbg_error)usbg_ret));
			goto out;
		}
	}

	/* Remove gadget with USBG_RM_RECURSE flag to remove
	 * also its configurations, functions and strings */
	usbg_ret = usbg_rm_gadget(g, USBG_RM_RECURSE);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on gadget remove\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
	}

out:
	return usbg_ret;
}

// need to fix detach func
static volatile long syz_detach_gadget_impl(int uid)
{
	int usbg_ret;
	int ret = -1;
	usbg_state* s;
	usbg_gadget* g;
	const char* g_name;
	char g_name_target[10];
	sprintf(g_name_target, "g%d", uid);

	usbg_ret = usbg_init("/sys/kernel/config", &s);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on USB state init\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
		goto out1;
	}

	g = usbg_get_first_gadget(s);
	while (g != NULL) {
		/* Get current gadget attrs to be compared */
		g_name = usbg_get_gadget_name(g);

		/* Compare name with given values and remove if suitable */
		if (strcmp(g_name, g_name_target) == 0) {
			usbg_gadget* g_next = usbg_get_next_gadget(g);

			usbg_ret = remove_gadget(g);
			if (usbg_ret != USBG_SUCCESS)
				goto out2;

			g = g_next;
		} else {
			g = usbg_get_next_gadget(g);
		}
	}
	usleep(500000);
	ret = 0;

out2:
	usbg_cleanup(s);
out1:
	return ret;
}

static volatile long syz_attach_gadget_impl(struct usb_gadget_device* dev, int uid)
{
	syz_detach_gadget_impl(uid);

	usbg_state* s;
	usbg_gadget* g;
	usbg_config* c;
	usbg_function* f[MAX_FUNC_NUM];
	usbg_udc* u;

	int ret = -1;
	int usbg_ret;

	char g_name[10];
	sprintf(g_name, "g%d", uid);

	usbg_ret = usbg_init("/sys/kernel/config", &s);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on usbg init\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
		goto out1;
	}

	usbg_ret = usbg_create_gadget(s, g_name, dev->g_attrs, &g_strs, &g);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on creating gadget\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
		goto out2;
	}

	for (int i = 0; i < dev->func_num; i++) {
		char f_name[10];
		sprintf(f_name, "func%d", i);

		if (dev->func_conf[i].f_attrs.default_attr == 0xffff)
			usbg_ret = usbg_create_function(g, dev->func_conf[i].f_type, (char*)f_name, NULL, &f[i]);
		else
			usbg_ret = usbg_create_function(g, dev->func_conf[i].f_type, (char*)f_name, &(dev->func_conf[i].f_attrs), &f[i]);
		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error on creating gadget func\n");
			fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
				usbg_strerror((usbg_error)usbg_ret));
			goto out2;
		}
	}

	usbg_ret = usbg_create_config(g, 1, "The only one config", dev->c_attrs, &c_strs, &c);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on creating gadget config\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
		goto out2;
	}

	for (int i = 0; i < dev->func_num; i++) {
		char f_name[10];
		sprintf(f_name, "f_name.%d", i);
		usbg_ret = usbg_add_config_function(c, (char*)f_name, f[i]);

		if (usbg_ret != USBG_SUCCESS) {
			fprintf(stderr, "Error on adding func to config\n");
			fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
				usbg_strerror((usbg_error)usbg_ret));
			goto out2;
		}
	}

	u = usbg_get_first_udc(s);
	if (uid > 0) {
		for (int i = 0; i < uid; i++) {
			u = usbg_get_next_udc(u);
		}
	}
	usbg_ret = usbg_enable_gadget(g, u);
	if (usbg_ret != USBG_SUCCESS) {
		fprintf(stderr, "Error on enabling udc\n");
		fprintf(stderr, "Error: %s : %s\n", usbg_error_name((usbg_error)usbg_ret),
			usbg_strerror((usbg_error)usbg_ret));
		goto out2;
	}

	ret = 0;

out2:
	usbg_cleanup(s);

out1:
	return ret;
}

// // print all fileds in struct usb_gadget_device
// static void print_usb_gadget_device(struct usb_gadget_device* dev)
// {
// 	printf("bcdUSB: %x\n", dev->g_attrs->bcdUSB);
// 	printf("bDeviceClass: %x\n", dev->g_attrs->bDeviceClass);
// 	printf("bDeviceSubClass: %x\n", dev->g_attrs->bDeviceSubClass);
// 	printf("bDeviceProtocol: %x\n", dev->g_attrs->bDeviceProtocol);
// 	printf("bMaxPacketSize0: %x\n", dev->g_attrs->bMaxPacketSize0);
// 	printf("idVendor: %x\n", dev->g_attrs->idVendor);
// 	printf("idProduct: %x\n", dev->g_attrs->idProduct);
// 	printf("bcdDevice: %x\n", dev->g_attrs->bcdDevice);
// 	printf("bmAttributes: %x\n", dev->c_attrs->bmAttributes);
// 	printf("bMaxPower: %x\n", dev->c_attrs->bMaxPower);
// 	printf("func_num: %d\n", dev->func_num);
// 	printf("func_conf.f_type: %d\n", dev->func_conf[0].f_type);
// }

static void parse_dev_descriptors(const char* buffer, struct usb_gadget_device* dev)
{
	// clear last struct buffer
	memset(dev, 0, sizeof(*dev));

	// pasre all structs
	dev->g_attrs = (struct usbg_gadget_attrs*)buffer;
	dev->c_attrs = (struct usbg_config_attrs*)(buffer + sizeof(struct usbg_gadget_attrs));
	dev->func_num = *(int*)(buffer + sizeof(struct usbg_gadget_attrs) + sizeof(struct usbg_config_attrs) + sizeof(int16_t));
	// printf("sizeof union: %lx\n", sizeof(struct usbg_func_config));
	int start_attr = sizeof(struct usbg_gadget_attrs) + sizeof(struct usbg_config_attrs) + sizeof(int16_t) + 2 * sizeof(int32_t);
	// int conf_size = sizeof(dev->func_conf) / MAX_FUNC_NUM;
	int conf_size = 40;
	for (int i = 0; i < dev->func_num; i++) {
		dev->func_conf[i] = *(struct usbg_func_config*)(buffer + start_attr + i * conf_size);
		// printf("func_conf[%d].f_type: %d\n", i, dev->func_conf[i].f_type);
		// printf("func_conf[%d] addr: %lx\n", i, (long unsigned int)(&dev->func_conf[i]));
		// printf("func_conf[%d].f_attr addr: %lx\n", i, (long unsigned int)(&dev->func_conf[i].f_attrs));
		// fix len of report_desc
		if (dev->func_conf[i].f_type == USBG_F_HID) {
			struct usbg_f_hid_attrs* hid_attr = &(dev->func_conf[i].f_attrs.hid_attr);
			struct usbg_f_hid_report_desc* report_desc = &(hid_attr->report_desc);
			// printf("protocol: %d\n", hid_attr->protocol);
			// printf("report_desc.desc: %s\n", (report_desc->desc));
			// printf("report_length: %d\n", hid_attr->report_length);
			// printf("subclass: %d\n", hid_attr->subclass);

			report_desc->len = strlen(report_desc->desc);
			// printf("report_desc->len: %x\n", report_desc->len);
			conf_size = 48;
			// printf("updated conf_size: %x\n", conf_size);
		}
	}
	// print_usb_gadget_device(dev);
}

static volatile long syz_attach_gadget(volatile long a0, volatile long a1)
{
	const char* dev = (const char*)a0;
	uint64 uid = a1;
	parse_dev_descriptors(dev, &usb_device[uid]);
	return syz_attach_gadget_impl(&usb_device[uid], uid);
}

#endif

// #if SYZ_EXECUTOR || __NR_syz_detach_gadget
// static volatile long syz_detach_gadget(volatile long a0)
// {
// 	int uid = a0;
// 	return syz_detach_gadget_impl(uid);
// }
// #endif