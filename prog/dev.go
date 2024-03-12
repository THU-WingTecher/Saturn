package prog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// map for fops and resource
var FopsResMap = map[string]string{
	"msr_fops":                    "fd_msr",
	"snapshot_fops":               "fd_snapshot",
	"posix_clock_file_operations": "fd_ptp",
	"dev_fops":                    "fd",
	"monitor_device_fops":         "fd",
	"ctl_device_fops":             "fd",
	"_dev_ioctl_fops":             "fd_autofs",
	"ocfs2_control_fops":          "fd",
	"btrfs_ctl_fops":              "fd",
	"vga_arb_device_fops":         "fd_vga_arbiter",
	"fb_fops":                     "fd_fb",
	"tty_fops":                    "fd_tty",
	"console_fops":                "fd",
	"ptmx_fops":                   "fd_tty",
	"vcs_fops":                    "fd_general",
	"null_fops":                   "fd_general",
	"zero_fops":                   "fd_general",
	"full_fops":                   "fd_general",
	"hpet_fops":                   "fd_general",
	"nvram_misc_fops":             "fd_general",
	"rng_chrdev_ops":              "fd_general",
	"vgem_driver_fops":            "fd_dri",
	"vkms_driver_fops":            "fd_dri",
	"bochs_fops":                  "fd_dri",
	"loop_ctl_fops":               "fd_loop_ctrl",
	"vmuser_fops":                 "fd_vmci",
	"udmabuf_fops":                "fd_udambuf",
	"sg_fops":                     "fd_sg",
	"nvmf_dev_fops":               "fd",
	"tun_fops":                    "fd_tun",
	"ppp_device_fops":             "fd_ppp",
	"vfio_fops":                   "fd_vfio",
	"mon_fops_binary":             "fd_usbmon",
	"userio_fops":                 "fd_userio",
	"mousedev_fops":               "fd",
	"evdev_fops":                  "fd_evdev",
	"uinput_fops":                 "fd_uinput",
	"rtc_dev_fops":                "fd_rtc",
	"media_devnode_fops":          "fd_media",
	"v4l2_fops":                   "fd_video",
	"capi_fops":                   "fd_capi20",
	"mISDN_fops":                  "fd_misdntimer",
	"ucma_fops":                   "fd_rdma_cm",
	"adf_ctl_ops":                 "fd_qat",
	"uhid_fops":                   "fd_uhid",
	"vhost_net_fops":              "vhost_net",
	"vhost_vsock_fops":            "vhost_vsock",
	"snd_ctl_f_ops":               "fd_sndctrl",
	"snd_timer_f_ops":             "fd_sndtimer",
	"snd_rawmidi_f_ops":           "fd_midi",
	"snd_mixer_oss_f_ops":         "fd_mixer",
	"snd_pcm_oss_f_reg":           "fd_dsp",
	"snd_seq_f_ops":               "fd_sndseq",
	"seq_oss_f_ops":               "fd_seq",
	"rfkill_fops":                 "fd_rfkill",
	"vsock_device_ops":            "fd",
	"qrtr_tun_ops":                "fd_qrtr_tun",
	"random_fops":                 "fd_random",
	"cachefiles_daemon_fops":      "fd",
	"simple_dir_operations":       "fd",
	"fuse_dev_operations":         "fd_fuse",
	"urandom_fops":                "fd_random",
	"cec_devnode_fops":            "fd_video",
	"ubi_ctrl_cdev_operations":    "fd_general",
	"def_blk_fops":                "fd_block",
	"snd_pcm_f_ops":               "fd_snd_dsp",
	"usbdev_file_operations":      "fd_usbfs",
	"hidraw_ops":                  "fd_hidraw",
	"hiddev_fops":                 "fd_hiddev",
	"i2cdev_fops":                 "fd_i2c",
	"bsg_fops":                    "fd_dev_bsg",
	"ext4_dir_operations":         "fd",
	"snd_hwdep_f_ops":             "fd_snd_hw",
	"printer_io_operations":       "fd_printer",
	"usblp_fops":                  "fd_lp",
	"tap_fops":                    "fd_tap",
	"wdm_fops":                    "fd_wdm",
	"comedi_fops":                 "fd_comedi",
	"f_hidg_fops":                 "fd_general",
	"ftdi_elan_fops":              "fd_general",
	"as102_dev_fops":              "fd_general",
}

// def_blk_fops: fd_blk, fd_nbd

func GetDevInfo(rawDevs []string, timeout time.Duration) ([]string, error) {
	devFilePath := "/dev"
	var devsDiff []string
	updateFiles := make([]string, 0)

	finish := make(chan bool)
	go func() {
		for {
			updateFiles, _ = ReadFileNamesRe(devFilePath)

			if len(updateFiles) > len(rawDevs) {
				finish <- true
				return
			}
		}
	}()

	select {
	case <-finish:
		idx := 0
		waitTime := time.Second * 0
		// magic number, too low!
		waitDuration := time.Millisecond * 800
		if checkMs(diff(rawDevs, updateFiles)) {
			waitDuration = time.Millisecond * 1600
		}
		fileNum := len(rawDevs)

		for {
			durationWaitTime := (1 << uint(idx)) * waitDuration
			fmt.Println("durationWaitTime: ", durationWaitTime)
			time.Sleep(durationWaitTime)
			updateFiles, _ := ReadFileNamesRe(devFilePath)
			if len(updateFiles) == fileNum {
				break
			}
			idx++
			fileNum = len(updateFiles)

			waitTime += durationWaitTime
			if waitTime > timeout {
				break
			}
		}
		updateFiles, _ = ReadFileNamesRe(devFilePath)
		devsDiff = diff(rawDevs, updateFiles)

	case <-time.After(timeout):
		return devsDiff, fmt.Errorf("timeout")
	}

	if len(devsDiff) == 0 {
		return devsDiff, fmt.Errorf("No-devices")
	}

	// remove item in the devsDiff if it is a symbol link
	for i := 0; i < len(devsDiff); i++ {
		if isSymlink(devsDiff[i]) {
			devsDiff = append(devsDiff[:i], devsDiff[i+1:]...)
			i--
		}
	}

	return devsDiff, nil
}

func checkMs(devs []string) bool {
	for _, dev := range devs {
		basename := filepath.Base(dev)
		if strings.HasPrefix(basename, "189") {
			return true
		}
	}
	return false
}

// diff two slices
func diff(b, a []string) []string {
	m := make(map[string]bool)
	for _, item := range b {
		m[item] = true
	}
	var result []string
	for _, item := range a {
		if _, ok := m[item]; !ok {
			result = append(result, item)
		}
	}
	return result
}

// Recursively read all the file names under the folder, full path
func ReadFileNamesRe(path string) ([]string, error) {
	var fileList []string
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fileList, nil
}

// check file if it is symbol link
func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

/* Receive file names as parameters and then open them */
func OpenFiles(files []string) {
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			fmt.Println(err)
		}
		f.Close()
	}
}

func logLossFops(fops string, devName string) {
	filePath := "/root/fops"
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		file, _ = os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	}

	defer file.Close()
	write := bufio.NewWriter(file)
	write.WriteString(fops + " " + devName + "\n")
	write.Flush()
}

func ConvertPath(path string) (ret string) {
	// covert path "/dev/bus/usb/001/001" to 001/001/usb/bus/
	ret = ""
	pathSilce := strings.Split(path, "/")
	for i := len(pathSilce) - 1; i > 1; i-- {
		ret = ret + pathSilce[i] + "/"
	}
	return
}
