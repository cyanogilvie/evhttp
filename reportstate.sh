#!/bin/sh

echo "-- $0 -----------------------------"
echo "user: $(id -u)"
echo "nice: $(nice)"

for f in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor /sys/devices/system/cpu/*/online
do
	if [ -e "$f" ]
	then
		echo "$f: \"$(cat "$f")\""
	fi
done

f=/sys/devices/system/cpu/cpufreq/boost
if [ -e "$f" ]
then
	echo "$f: \"$(cat "$f")\""
else
	echo "turbo disabled: $(rdmsr 0x1a0 --bitfield 38:38)"
fi

echo "--------------------------------------"
exit 0
