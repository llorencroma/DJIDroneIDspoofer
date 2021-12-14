#!/bin/bash



echo "Interfaces"
ip -br link | awk '{ print $1}'

read -p "Interface name: " interface

sudo ip link set $interface down
sudo iwconfig $interface mode monitor
sudo ip link set $interface up

echo "What do you want to do: "
echo "> Spoof one drone (1)"
echo "> Spoof multiple drones (2)"
echo "> Spoof multiple drones around a location (3)"

read mode

case $mode in 
    '1')
        sudo python3 main.py -i $interface
    ;;
    '2')
        read -p "> How many drones to spoof: " x_drones
        sudo python3 main.py -i $interface -r $x_drones
    ;;
    '3')
        read -p "> How many drones to spoof: " x_drones
        read -p "> Latitude,Longitude: " coordinates

        sudo python3 main.py -i $interface -r $x_drones -a \'$coordinates\'
    ;;
esac
