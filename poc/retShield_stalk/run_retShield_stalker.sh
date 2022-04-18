#!/bin/bash

scr="./retShield_stalker"
sudo frida prog_32b -l ${scr}.js 2>&1 | tee ${scr}.txt
