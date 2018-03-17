---
date: 2018-03-17 13:55
status: public
title: sim
---

# Network-Communication-Simulation
A GUI program that simulates network communication, base on Python Tk

## Network Model

It's base on TCP/IP network model
The difference  is that  in  this model I  added a physical layer, then it come to a 5 layers network communication model.

![](https://github.com/WananpIG/Network-Communication-Simulation/tree/master/_image/README/13-57-40.jpg)

## Feature

Strictly implemented the rules of paking &unpaking and data packet structure at each layer, contained dynamic menu. It also can send arbitrary characters, control the packets length and  reorganized unsorted packets in network layer.
There two windows. one to parse  the actualy meaning of each packet data, and another on to show up  Hex of data.
The structure of each layer, there are shows in the source code.
The GUI lib is the Python own lib -- tkinter, which doesn't need to be installed
The code can be run in python 2.7 environment.

##The program looks like this

![](https://github.com/WananpIG/Network-Communication-Simulation/blob/master/_image/README/14-25-11.jpg)


![](https://github.com/WananpIG/Network-Communication-Simulation/blob/master/_image/README/14-26-23.jpg)




