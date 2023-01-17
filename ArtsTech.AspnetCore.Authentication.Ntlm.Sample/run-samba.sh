﻿#!/bin/sh

samba-tool domain provision  \
    --realm samdom.example.com \
    --domain samdom \
    --adminpass P@ssword123 \
    --dns-backend=SAMBA_INTERNAL \
    --server-role=dc 
samba-tool user create alice Hunter2
samba-tool user create bob CorrectHorseBatteryStaple
samba-tool user create eve Tr0ub4dor&3
