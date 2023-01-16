#!/bin/sh

samba-tool domain provision  \
    --realm samdom.example.com \
    --domain samdom \
    --adminpass P@ssword123 \
    --dns-backend=SAMBA_INTERNAL \
    --server-role=dc 
samba-tool user create user1 S3cret123
samba-tool user create user2 S3cret123
