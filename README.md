## Malware detection using task_struct

Author: `chinmay_dd`

## Running

[1] `make`  - to compile the kernel module.<br/>
[2] `sudo insmod proj.ko` - to add the kernel module.<br/>
[3] `dmesg` to view if it was added properly.<br/>
[4] `cat data.txt` - to check if the data was written to the file.<br/>
[5] `sudo rmmod proj` - to remove the module.<br/>

## License

MIT
