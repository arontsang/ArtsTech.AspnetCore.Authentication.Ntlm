#!/bin/sh

samba-tool domain provision  \
    --realm samdom.example.com \
    --domain samdom \
    --adminpass P@ssword123 \
    --dns-backend=SAMBA_INTERNAL \
    --server-role=dc 
samba-tool user create alice Hunter2
samba-tool user create bob CorrectHorseBatteryStaple1
samba-tool user create eve Tr0ub4dor&3

samba-tool group add trusted-users
samba-tool group add users

samba-tool group addmembers trusted-users alice,bob
