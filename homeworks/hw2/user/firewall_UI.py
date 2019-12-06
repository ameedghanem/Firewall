import os, sys
DEVICE_PATH = "/sys/class/Sysfs_class/sysfs_class_sysfs_Device/sysfs_att"

if(len(sys.argv) == 2):
	if(int(sys.argv[1]) != 0):
		sys.exit("Error: Invalid Input Number")
	else:
		with open(DEVICE_PATH, "w+") as writer:
			zero = "0"
			writer.write(zero)
elif len(sys.argv) > 2:
	sys.exit("Error: Invalid Number of agruments")
else:
	with open(DEVICE_PATH) as reader:
		data = reader.readline(50)
	data1 = str(data)
	status = data1.split(',')#I stored these numbers separated by a comma.
	accepted = int(status[0])
	dropped  = int(status[1])

	print("Firewall Packets Summary:")
	print("Number of accepted packets: %d" % accepted)
	print("Number of dropped packets: %d" % dropped)
	print("Total number of packets: %d" % (accepted + dropped))
