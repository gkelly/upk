# Copyright 2010 Garret Kelly. All Rights Reserved.
# Author: gkelly@gkelly.org (Garret Kelly)

obj-m += upk.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
