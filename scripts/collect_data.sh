#!/bin/bash
for filename in /home/krypt0/MalwareAnalysis/elfs/*; do
    proc_name=${filename: -4}
    data_path="/home/krypt0/MalwareAnalysis/data/"$proc_name".txt"

    touch $data_path
    insmod proj.ko ELF_PATH=$filename DATA_PATH=$data_path PROC_NAME=$proc_name
    rmmod proj
done
