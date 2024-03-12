// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const (
	USB_DEVICE_ID_MATCH_VENDOR = 1 << iota
	USB_DEVICE_ID_MATCH_PRODUCT
	USB_DEVICE_ID_MATCH_DEV_LO
	USB_DEVICE_ID_MATCH_DEV_HI
	USB_DEVICE_ID_MATCH_DEV_CLASS
	USB_DEVICE_ID_MATCH_DEV_SUBCLASS
	USB_DEVICE_ID_MATCH_DEV_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_CLASS
	USB_DEVICE_ID_MATCH_INT_SUBCLASS
	USB_DEVICE_ID_MATCH_INT_PROTOCOL
	USB_DEVICE_ID_MATCH_INT_NUMBER

	BytesPerUsbID = 17
	BytesPerHidID = 12
)

const (
	USBG_F_SERIAL = iota
	USBG_F_ACM
	USBG_F_OBEX
	USBG_F_ECM
	USBG_F_SUBSET
	USBG_F_NCM
	USBG_F_EEM
	USBG_F_RNDIS
	USBG_F_PHONET
	USBG_F_FFS
	USBG_F_MASS_STORAGE
	USBG_F_MIDI
	USBG_F_LOOPBACK
	USBG_F_HID
	USBG_F_UAC2
	USBG_F_UVC
	USBG_F_PRINTER
	USBG_FUNCTION_TYPE_MAX
)

// func attr and []func type mapping
var funcAttrMap = map[int][]int{
	0:  {USBG_F_SERIAL},
	1:  {USBG_F_ECM, USBG_F_NCM, USBG_F_ECM, USBG_F_SUBSET, USBG_F_EEM, USBG_F_RNDIS},
	2:  {USBG_F_OBEX}, // BLUETOOTH
	3:  {USBG_F_PHONET},
	4:  {USBG_F_MASS_STORAGE},
	5:  {USBG_F_MIDI},
	6:  {USBG_F_PRINTER},
	7:  {USBG_F_LOOPBACK},
	8:  {USBG_F_MIDI},
	9:  {USBG_F_MASS_STORAGE},
	10: {USBG_F_ECM, USBG_F_NCM, USBG_F_ECM, USBG_F_SUBSET, USBG_F_EEM, USBG_F_RNDIS},
}

type UsbDeviceID struct {
	MatchFlags         uint16
	IDVendor           uint16
	IDProduct          uint16
	BcdDeviceLo        uint16
	BcdDeviceHi        uint16
	BDeviceClass       uint8
	BDeviceSubClass    uint8
	BDeviceProtocol    uint8
	BInterfaceClass    uint8
	BInterfaceSubClass uint8
	BInterfaceProtocol uint8
	BInterfaceNumber   uint8
}

type HidDeviceID struct {
	Bus     uint16
	Group   uint16
	Vendor  uint32
	Product uint32
}

func (arch *arch) generateUsbDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	id := randUsbDeviceID(g, true)
	bcdDevice := id.BcdDeviceLo + uint16(g.Rand().Intn(int(id.BcdDeviceHi-id.BcdDeviceLo)+1))

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.IDVendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.IDProduct))
	patchGroupArg(devArg, 9, "bcdDevice", uint64(bcdDevice))
	patchGroupArg(devArg, 3, "bDeviceClass", uint64(id.BDeviceClass))
	patchGroupArg(devArg, 4, "bDeviceSubClass", uint64(id.BDeviceSubClass))
	patchGroupArg(devArg, 5, "bDeviceProtocol", uint64(id.BDeviceProtocol))

	configArg := devArg.(*prog.GroupArg).Inner[14].(*prog.GroupArg).Inner[0].(*prog.GroupArg).Inner[0]
	interfacesArg := configArg.(*prog.GroupArg).Inner[8]

	for i, interfaceArg := range interfacesArg.(*prog.GroupArg).Inner {
		interfaceArg = interfaceArg.(*prog.GroupArg).Inner[0]
		if i > 0 {
			// Generate new IDs for every interface after the first one.
			id = randUsbDeviceID(g, true)
		}
		patchGroupArg(interfaceArg, 5, "bInterfaceClass", uint64(id.BInterfaceClass))
		patchGroupArg(interfaceArg, 6, "bInterfaceSubClass", uint64(id.BInterfaceSubClass))
		patchGroupArg(interfaceArg, 7, "bInterfaceProtocol", uint64(id.BInterfaceProtocol))
		patchGroupArg(interfaceArg, 2, "bInterfaceNumber", uint64(id.BInterfaceNumber))
	}

	return
}

func (arch *arch) generateGadgetDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	id := randUsbDeviceID(g, false)
	bcdDevice := id.BcdDeviceLo + uint16(g.Rand().Intn(int(id.BcdDeviceHi-id.BcdDeviceLo)+1))
	if id.BcdDeviceLo == id.BcdDeviceHi {
		bcdDevice = id.BcdDeviceLo
	}

	devArg := arg.(*prog.GroupArg)
	patchGroupArg(devArg, 5, "idVendor", uint64(id.IDVendor))
	patchGroupArg(devArg, 6, "idProduct", uint64(id.IDProduct))
	patchGroupArg(devArg, 7, "bcdDevice", uint64(bcdDevice))
	patchGroupArg(devArg, 1, "bDeviceClass", uint64(id.BDeviceClass))
	patchGroupArg(devArg, 2, "bDeviceSubClass", uint64(id.BDeviceSubClass))
	patchGroupArg(devArg, 3, "bDeviceProtocol", uint64(id.BDeviceProtocol))

	// a.Inner[index].(*prog.ConstArg).Val = value
	numConfig := devArg.Inner[11].(*prog.ConstArg).Val
	// fmt.Println("config len:", len(devArg.Inner)) // 14 elements totally
	configArg := devArg.Inner[13].(*prog.GroupArg)

	for i := 0; i < int(numConfig); i++ {
		if i >= len(configArg.Inner) {
			break
		}
		intfArg := configArg.Inner[i].(*prog.GroupArg)
		funcArg := intfArg.Inner[2].(*prog.UnionArg)
		// select one from slice funcAttrMap[funcArg.Index]
		index := g.Rand().Intn(len(funcAttrMap[funcArg.Index]))
		// fmt.Println(funcAttrMap[funcArg.Index][index])
		patchGroupArg(intfArg, 0, "f_type", uint64(funcAttrMap[funcArg.Index][index]))

	}

	// checkGenerate(devArg)

	// maybe we can do nothing for interface descriptors
	return
}

func randUsbDeviceID(g *prog.Gen, mutate bool) UsbDeviceID {
	totalIds := len(usbIds) / BytesPerUsbID
	idNum := g.Rand().Intn(totalIds)
	base := usbIds[idNum*BytesPerUsbID : (idNum+1)*BytesPerUsbID]

	p := strings.NewReader(base)
	var id UsbDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	if mutate {
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_VENDOR) == 0 {
			id.IDVendor = uint16(g.Rand().Intn(0xffff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_PRODUCT) == 0 {
			id.IDProduct = uint16(g.Rand().Intn(0xffff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_LO) == 0 {
			id.BcdDeviceLo = 0x0
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_HI) == 0 {
			id.BcdDeviceHi = 0xffff
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_CLASS) == 0 {
			id.BDeviceClass = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) == 0 {
			id.BDeviceSubClass = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) == 0 {
			id.BDeviceProtocol = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_CLASS) == 0 {
			id.BInterfaceClass = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) == 0 {
			id.BInterfaceSubClass = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) == 0 {
			id.BInterfaceProtocol = uint8(g.Rand().Intn(0xff + 1))
		}
		if (id.MatchFlags & USB_DEVICE_ID_MATCH_INT_NUMBER) == 0 {
			id.BInterfaceNumber = uint8(g.Rand().Intn(0xff + 1))
		}
	}
	return id
}

func (arch *arch) generateUsbHidDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	totalIds := len(hidIds) / BytesPerHidID
	idNum := g.Rand().Intn(totalIds)
	base := hidIds[idNum*BytesPerHidID : (idNum+1)*BytesPerHidID]

	p := strings.NewReader(base)
	var id HidDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}

	devArg := arg.(*prog.GroupArg).Inner[0]
	patchGroupArg(devArg, 7, "idVendor", uint64(id.Vendor))
	patchGroupArg(devArg, 8, "idProduct", uint64(id.Product))

	return
}

func (arch *arch) generateHidGadgetDeviceDescriptor(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ0, dir, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}

	totalIds := len(hidIds) / BytesPerHidID
	idNum := g.Rand().Intn(totalIds)
	base := hidIds[idNum*BytesPerHidID : (idNum+1)*BytesPerHidID]

	p := strings.NewReader(base)
	var id HidDeviceID
	if binary.Read(p, binary.LittleEndian, &id) != nil {
		panic("not enough data to read")
	}
	devArg := arg.(*prog.GroupArg)
	patchGroupArg(devArg, 5, "idVendor", uint64(id.Vendor))
	patchGroupArg(devArg, 6, "idProduct", uint64(id.Product))

	checkGenerate(devArg)

	return
}

func patchGroupArg(arg prog.Arg, index int, field string, value uint64) {
	a := arg.(*prog.GroupArg)
	typ := a.Type().(*prog.StructType)
	if field != typ.Fields[index].Name {
		panic(fmt.Sprintf("bad field, expected %v, found %v", field, typ.Fields[index].Name))
	}
	a.Inner[index].(*prog.ConstArg).Val = value
}

func checkGenerate(arg prog.Arg) {
	a := arg.(*prog.GroupArg)
	typ := a.Type().(*prog.StructType)
	// print all the fields
	for i, f := range typ.Fields {

		fmt.Printf("xxx index: %d, name: %v, size: %d\n", i, f.Name, a.Inner[i].Size())
		// fmt.Printf("111 index: %d, %v: %x\n", i, f.Name, a.Inner[i].(*prog.ConstArg).Val)
		// fmt.Println("val: ", a.Inner[i].(*prog.ConstArg).Val)
	}
}
