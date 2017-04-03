## Malware detection using task_struct

Author: chinmay_dd

## Running

[1] `make`  - to compile the kernel module.
[2] `sudo insmod proj.ko` - to add the kernel module.
[3] `dmesg` to view if it was added properly.
[4] `cat data.txt` - to check if the data was written to the file.
[5] `sudo rmmod proj` - to remove the module.

## License

MIT
