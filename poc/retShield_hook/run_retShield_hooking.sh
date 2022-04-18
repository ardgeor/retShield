#!/bin/bash

scr="./retShield_hooking"
sudo frida prog_32b -l ${scr}.js 2>&1 | tee ${scr}.txt
