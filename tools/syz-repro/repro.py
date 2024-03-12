import os

def read_dir(dir_path):
    files = []
    for file in os.listdir(dir_path):
        files.append(dir_path + '/' + file)
    return files

def exec_cmd_and_wait(cmd):
    print(cmd)
    os.system(cmd)


def generate_cmd(path):
    # find all file in the path
    for file in os.listdir(path):
        # find file exist in the path
        if os.path.exists(path+"/repro.txt"):
            break
        if file.startswith("log"):
            cmd = "./bin/syz-repro -config=usb1.cfg " + path + "/" + file
            # write to file
            with open("commands.log", "a") as f:
                f.write(cmd + "\n")
            exec_cmd_and_wait(cmd)


def main():
    # Get the list of files in the current directory.
    crash_path = "/disk/usbfuzz/syzkaller-usb/crashes-repro"
    paths = read_dir(crash_path)
    for path in paths:
        # Generate the command to run the repro.
        generate_cmd(path)


if __name__ == "__main__":
    main()