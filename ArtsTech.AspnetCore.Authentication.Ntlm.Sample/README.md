# Sample

This sample is expected to be run in Docker under privileged mode.

run-samba.sh Will build up a samba instance with some test users for you to test against.

WinbindService will run `run-samba.sh` and then start the `samba` backend, before AspNetCore starts up.

### Example passwords

| User         | Password                  |
|--------------|---------------------------|
| adminstrator | P@ssword123               |
| alice        | Hunter2                   |
| bob          | CorrectHorseBatteryStaple |
| eve          | Tr0ub4dor&3               |