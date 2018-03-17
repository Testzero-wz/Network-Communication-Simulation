# -*- coding: UTF-8 -*-
import time, random
from Tkinter import *
from ScrolledText import ScrolledText
import sys
reload(sys)
sys.setdefaultencoding('UTF-8')


MTU = 100  #Maximum Transport Unit: 数据链路层最大传送数据单元
IP_MSS = MTU - 20  #IP_Maximum Segment Size: 网络层(IP)数据包数据最大大小

#本程序用UDP演示,且规定了MAS,故并未使用MSS
MSS = MTU - 20 - 20  #Maximum Segment Size: 传输层(TCP)数据包数据最大大小


MAS = 360   #Maximum Segment Size:应用层(自定义)数据报大小上限
# MAS = (65535-20-8-10-1)/2 #MAS推荐上限

#应用层
'''
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Application  Header 10字节     |               Data                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|48位 时间戳   |  32位 Data长度 |   Data 遵循UDP最大包,编码utf-16     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

'''


def applicationLayer(_data):
    stream = hex(int(time.time()))[2:].zfill(12) + hex(len(_data))[2:].zfill(8)

    for i in range(len(_data)):
        stream += hex(ord(_data[i]))[2:].zfill(4)
    return stream


def unPakingApplicationLayer(_data):
    string = _data[20:]
    Time = time.strftime('%Y-%m-%d %X', time.localtime(int(_data[:12], 16)))
    length = str(int(_data[12:20], 16))
    data = u""
    chr = u""
    for i in range(len(string) / 4):
        try:
            chr = unichr(int(string[4 * i:4 * i + 4], 16))
        except:
            chr = "?"
        data += chr

    return data, {'data': data, 'time': Time, 'length': length}


#传输层  UDP模拟
'''
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Source   Port          |        Destination   Port      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        UDP   Lengt           |           CheckSum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''


def UDP(_data):
    return "0080" + "f27c" + str(
        hex(len(_data) / 2 + 8))[2:].zfill(4) + "0000" + _data


def unPackingUDP(_data):
    sPort = _data[:4]
    dPort = _data[4:8]
    length = _data[8:12]
    checkSum = _data[12:16]
    data = _data[16:]
    return data, {
        'SourcePort': sPort,
        'DestinationPort': dPort,
        'Length': length,
        'CheckSum': checkSum,
        'Data': data
    }


#网络层 IP协议
'''
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| IHL | Type of Service|          Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Identification         |Flags|        Fragment Offset   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Time to Live |   Protocol    |       Header Checksum          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address               ,         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Destination Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Options             |             Padding            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''


def IP(_data):
    version = '4'
    IHL = '5'
    TOS = '00'
    totalLength = ''  #
    identification = hex(random.randint(0, 2**16 - 1))[2:].zfill(4)
    evilFlag = 0
    DF = 0  #
    MF = 0  #
    fragmentOffset = 0
    TT = 'ff'
    #https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    protocol = '11'  #UDP
    checkSum = '0000'
    sIP = '0a0c0a9b'  #10.12.10.155
    dIP = '765923c0'  #118.89.35.192
    ip_stream = []
    if len(_data) / 2 / IP_MSS + 1 == 1:
        totalLength = str(len(_data) / 2 + 20).zfill(4)
        return [
            version + IHL + TOS + totalLength + identification + "0000" + TT +
            protocol + checkSum + sIP + dIP + _data[:IP_MSS * 2]
        ]
    for i in range(len(_data) / 2 / IP_MSS + 1):
        totalLength = str(
            len(_data[2 * i * IP_MSS:(i + 1) * IP_MSS * 2]) / 2 + 20).zfill(4)
        ip_stream.append(version+IHL+TOS+totalLength+identification+hex(i*IP_MSS+((1 if i==(len(_data)/2/IP_MSS) else 0)<<13))[2:].zfill(4)\
                         +TT+protocol+checkSum+sIP+dIP+_data[2*i*IP_MSS:(i+1)*IP_MSS*2])
    return ip_stream


def unPackingIP(_data):
    version = _data[0]
    IHL = _data[1]
    TOS = _data[2:4]
    totalLength = _data[4:8]  #
    identification = _data[8:12]
    evilFlag = bin(int(_data[12], 16))[2:].zfill(4)[3]
    DF = bin(int(_data[12], 16))[2:].zfill(4)[2]
    MF = bin(int(_data[12], 16))[2:].zfill(4)[1]
    fragmentOffset = str(
        int(_data[13:16], 16) + (
            (int(bin(int(_data[12], 16))[2:].zfill(4)[0])) << 12))
    TT = _data[16:18]
    #https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    protocol = _data[18:20]
    checkSum = _data[20:24]
    sIP = _data[24:32]  #10.12.10.155
    dIP = _data[32:40]  #118.89.35.192

    return  _data[40:],{'ProtocolVersion':version,'IHL':IHL,'TOS':TOS,'TotalLength':totalLength,\
            'Identification':identification,'EvilFlag':evilFlag,'Don\'tFragement':DF,'MoreFragment':MF,'FragmentOffset':fragmentOffset,\
            'Time to Live':TT,'Protocol':protocol,'CheckSum':checkSum,'SourceIP':sIP,'DestinationIP':dIP,'Data':_data[40:]
    }


#数据链路层 802.3帧格式
'''
btyes: 8              6                     6             2     0-1500      0-46       4
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+
|  Preamble | Destination Address |  Source Address  | Length |   Data   | Padding | CheckSum |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-++-+-+
'''


def linkLayer(_data):
    preamble = hex(int('10101010', 2))[2:] * 7 + hex(int('10101011', 2))[2:]
    dMAC = 'ffffffffffff'
    sMAC = '2047472ebaf8'
    data = _data if len(_data) / 2 > 46 else (_data +
                                              (46 - len(_data) / 2) * '0')
    length = hex(len(_data) / 2)[2:].zfill(4)
    checkSum = '00000000'
    return preamble + dMAC + sMAC + length + data + checkSum


def unPackingLinkLayer(_data):
    preamble = _data[:16]
    dMAC = _data[16:28]
    sMAC = _data[28:40]
    length = _data[40:44]
    data = _data[44:44 + int(length, 16) * 2]

    checkSum = str(_data[-8:])
    return data, {
        'Preamble': preamble,
        'DestionationMAC': dMAC,
        'SourceMAC': sMAC,
        'Data': data,
        'Length': length,
        'CheckSum': checkSum
    }


#物理层
def physicalLayer(_data):
    bitStream = ''
    for i in _data:
        bitStream += bin(int(i, 16))[2:].zfill(4)
    return bitStream


def unPackingPhysicalLayer(bitStream):
    return hex(int(bitStream, 2))[2:-1]


def packingData(event=""):
    global reApp_StreamList,reUDP_StreamList,reIP_StreamList,reLink_StreamList,rePhysical_StreamList,seApp_StreamList,seUDP_StreamList\
    ,seIP_StreamList,seLink_StreamList,sePhysical_StreamList
    #清除之前发包的菜单
    senderMenu.delete(0, 8)
    senderMenu.ApplicationLayer.delete(0, len(seApp_StreamList))
    senderMenu.TransportLayer.delete(0, len(seUDP_StreamList))
    senderMenu.NetworkLayer.delete(0, len(seIP_StreamList))
    senderMenu.LinkLayer.delete(0, len(seLink_StreamList))
    senderMenu.PhysicalLayer.delete(0, len(sePhysical_StreamList))

    receiverMenu.delete(0, 8)
    receiverMenu.ApplicationLayer.delete(0, len(reApp_StreamList))
    receiverMenu.TransportLayer.delete(0, len(reUDP_StreamList))
    receiverMenu.NetworkLayer.delete(0, len(reIP_StreamList))
    receiverMenu.LinkLayer.delete(0, len(reLink_StreamList))
    receiverMenu.PhysicalLayer.delete(0, len(rePhysical_StreamList))

    analysisText.config(state=NORMAL)
    dataText.config(state=NORMAL)
    analysisText.delete(0.0, END)
    dataText.delete(0.0, END)

    reApp_StreamList = []
    reUDP_StreamList = []
    reIP_StreamList = []
    reLink_StreamList = []
    rePhysical_StreamList = []

    seApp_StreamList = []
    seUDP_StreamList = []
    seIP_StreamList = []
    seLink_StreamList = []
    sePhysical_StreamList = []

    data = inputData.get("0.0", "end")
    if type(data).__name__ == 'str':
        data = data.decode('utf-8')

    #应用层程序封装数据包
    for i in range(len(data) / MAS + 1):
        seApp_StreamList.append(applicationLayer(data[i * MAS:(i + 1) * MAS]))
    #seApp_StreamList为我们需要发送的数据包
    for i in seApp_StreamList:
        l = []
        seUDP_StreamList.append(UDP(i))

        for j in IP(UDP(i)):
            l.append(j)
            #链路层数据包列表
            seLink_StreamList.append(linkLayer(j))
            #物理层数据包列表
            sePhysical_StreamList.append(physicalLayer(linkLayer(j)))
        #IP层数据包分别装，以便演示
        seIP_StreamList.append(l)

    #-----------------------------接收方--------------------------------------

    #物理层接收
    rePhysical_StreamList = sePhysical_StreamList[:]
    random.shuffle(rePhysical_StreamList)

    #物理层解码至链路层
    for i in rePhysical_StreamList:
        reLink_StreamList.append(unPackingPhysicalLayer(i))

    l = []
    #链路层解码至网络层
    for i in reLink_StreamList:
        l.append(unPackingLinkLayer(i)[0])
    #网络层IP协议解码重组
    l.sort(key=lambda x: x[8:12])  #以标识排序
    identification = l[0][8:12]
    buffList = []
    for i in l:
        if i[8:12] == identification:
            buffList.append(i)
        else:
            identification = i[8:12]
            reIP_StreamList.append(buffList)
            buffList = [i]
    reIP_StreamList.append(buffList)  #得到分组完毕的乱序IP包

    for i in reIP_StreamList:
        #按照IP包Header的分段偏移量FragmentOffet排序
        i.sort(key=lambda x:int(x[13:16],16)+((int(bin(int(x[12],16))[2:].zfill(4)[0]))<<12))
        stream = ''
        #重组成UDP包
        for j in i:
            stream += unPackingIP(j)[0]
        reUDP_StreamList.append(stream)
    #UDP解包至应用层
    for i in reUDP_StreamList:
        reApp_StreamList.append(unPackingUDP(i)[0])
    #创建菜单
    createMenu()


def createMenu():

    #Sender菜单更新
    for i in range(len(seApp_StreamList)):
        senderMenu.ApplicationLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(seApp_StreamList[x], 'Application')
        )
    for i in range(len(seUDP_StreamList)):
        senderMenu.TransportLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(seUDP_StreamList[x], 'Transport'))
    for i in range(len(seLink_StreamList)):
        senderMenu.LinkLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(seLink_StreamList[x], 'Link'))
    for i in range(len(sePhysical_StreamList)):
        senderMenu.PhysicalLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(sePhysical_StreamList[x], 'Physical')
        )
    #创建IP分组多级菜单
    variable = locals()
    for i in range(len(seIP_StreamList)):
        variable['IP_PackageMenu%s' % str(i + 1)] = Menu(
            senderMenu.NetworkLayer, tearoff=0)
        for j in range(len(seIP_StreamList[i])):
            variable['IP_PackageMenu%s' % str(i + 1)].add_command(
                label='IP数据包%s' % str(j + 1),
                command=
                lambda x=i, y=j: updateAnalysisFrame(seIP_StreamList[x][y], 'Network')
            )
        senderMenu.NetworkLayer.add_cascade(
            label='数据包%s' % str(i + 1),
            menu=variable['IP_PackageMenu%s' % str(i + 1)])

    #Receiver菜单更新
    for i in range(len(reApp_StreamList)):
        receiverMenu.ApplicationLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(reApp_StreamList[x], 'Application')
        )
    for i in range(len(reUDP_StreamList)):
        receiverMenu.TransportLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(reUDP_StreamList[x], 'Transport'))
    for i in range(len(reLink_StreamList)):
        receiverMenu.LinkLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(reLink_StreamList[x], 'Link'))
    for i in range(len(rePhysical_StreamList)):
        receiverMenu.PhysicalLayer.add_command(
            label='数据包%s' % str(i + 1),
            command=
            lambda x=i: updateAnalysisFrame(rePhysical_StreamList[x], 'Physical')
        )
    #创建IP分组多级菜单
    variable = locals()
    for i in range(len(reIP_StreamList)):
        variable['IP_PackageMenu%s' % str(i + 1)] = Menu(
            receiverMenu.NetworkLayer, tearoff=0)
        for j in range(len(reIP_StreamList[i])):
            variable['IP_PackageMenu%s' % str(i + 1)].add_command(
                label='IP数据包%s' % str(j + 1),
                command=
                lambda x=i, y=j: updateAnalysisFrame(reIP_StreamList[x][y], 'Network')
            )
        receiverMenu.NetworkLayer.add_cascade(
            label='数据包%s' % str(i + 1),
            menu=variable['IP_PackageMenu%s' % str(i + 1)])
    #重新添加
    senderMenu.add_cascade(label='应用层', menu=senderMenu.ApplicationLayer)
    senderMenu.add_separator()
    senderMenu.add_cascade(label='传输层', menu=senderMenu.TransportLayer)
    senderMenu.add_separator()
    senderMenu.add_cascade(label='网络层', menu=senderMenu.NetworkLayer)
    senderMenu.add_separator()
    senderMenu.add_cascade(label='链路层', menu=senderMenu.LinkLayer)
    senderMenu.add_separator()
    senderMenu.add_cascade(label='物理层', menu=senderMenu.PhysicalLayer)

    receiverMenu.add_cascade(label='应用层', menu=receiverMenu.ApplicationLayer)
    receiverMenu.add_separator()
    receiverMenu.add_cascade(label='传输层', menu=receiverMenu.TransportLayer)
    receiverMenu.add_separator()
    receiverMenu.add_cascade(label='网络层', menu=receiverMenu.NetworkLayer)
    receiverMenu.add_separator()
    receiverMenu.add_cascade(label='链路层', menu=receiverMenu.LinkLayer)
    receiverMenu.add_separator()
    receiverMenu.add_cascade(label='物理层', menu=receiverMenu.PhysicalLayer)


def updateAnalysisFrame(stream='', type='Physical'):

    analysisText.config(state=NORMAL)
    analysisText.delete(0.0, END)
    if type == "Application":
        unpackingDic = unPakingApplicationLayer(stream)[1]

    elif type == "Transport":
        unpackingDic = unPackingUDP(stream)[1]
    elif type == "Network":
        unpackingDic = unPackingIP(stream)[1]
    elif type == "Link":
        unpackingDic = unPackingLinkLayer(stream)[1]
    else:
        # unpackingDic = stream

        analysisText.insert(END, "BitStream:\n")
        analysisText.insert(END, "\t" + unPackingPhysicalLayer(stream) + "\n")
        updateDataFrame(stream)
        analysisText.config(state=DISABLED)
        return 0
    updateDataFrame(stream)

    for k in unpackingDic:
        analysisText.insert(END, k + ":\n")
        analysisText.insert(END, "\t" + unpackingDic[k] + "\n")
    analysisText.config(state=DISABLED)


def updateDataFrame(stream=''):
    '''
    * Due to the coding of input obtained from input widget is Unicode, which word length  can be 2 or 4 bytes(mostly are 2 bytes)
    * it may cause a chaos in DataFrame wighet
    * param stream: dataStream you want to analysis
    * return: void
    '''
    dataText.config(state=NORMAL)
    n = 0
    string = ' '
    char = ''
    dataText.delete(0.0, END)
    for i in range(0, len(stream), 2):
        if n == 8:
            string += '    '
        if n < 16:
            string += stream[i:i + 2] + " "
            if int(stream[i:i + 2],
                   16) != 0 and int(stream[i:i + 2], 16) != 0x0a and int(
                       stream[i:i + 2], 16) != 0x0b and int(
                           stream[i:i + 2], 16) != 0x09 and int(
                               stream[i:i + 2], 16) != 0x08:
                try:
                    char += chr(int(stream[i:i + 2], 16))
                except:
                    char += '.'
            else:
                char += '.'
        else:
            string += "           " + char
            dataText.insert(END, string + "\n")
            n = -1
            string = ' '
            char = ''
        n += 1
    dataText.insert(END, "%-53s" % string + "           " + char + "\n")
    dataText.config(state=DISABLED)


def selectText(event):
    event.widget.tag_add(SEL, "1.0", END)
    return 'break'

#-------------------------------------------主程序开始--------------------------------------------------------
#数组初始化
reApp_StreamList = []
reUDP_StreamList = []
reIP_StreamList = []
reLink_StreamList = []
rePhysical_StreamList = []

seApp_StreamList = []
seUDP_StreamList = []
seIP_StreamList = []
seLink_StreamList = []
sePhysical_StreamList = []

root = Tk()
root.title("网络传输模拟")

#主菜单
mainMenu = Menu(root)

senderMenu = Menu(mainMenu, tearoff=0)
#各层菜单
senderMenu.ApplicationLayer = Menu(senderMenu, tearoff=0)
senderMenu.TransportLayer = Menu(senderMenu, tearoff=0)
senderMenu.NetworkLayer = Menu(senderMenu, tearoff=0)
senderMenu.LinkLayer = Menu(senderMenu, tearoff=0)
senderMenu.PhysicalLayer = Menu(senderMenu, tearoff=0)
#Sender菜单添加进主菜单
mainMenu.add_cascade(label="  发送方  ", menu=senderMenu)

#各层添加进Sender菜单
senderMenu.add_cascade(label='应用层', menu=senderMenu.ApplicationLayer)
senderMenu.add_separator()
senderMenu.add_cascade(label='传输层', menu=senderMenu.TransportLayer)
senderMenu.add_separator()
senderMenu.add_cascade(label='网络层', menu=senderMenu.NetworkLayer)
senderMenu.add_separator()
senderMenu.add_cascade(label='链路层', menu=senderMenu.LinkLayer)
senderMenu.add_separator()
senderMenu.add_cascade(label='物理层', menu=senderMenu.PhysicalLayer)
#Receiver菜单
receiverMenu = Menu(mainMenu, tearoff=0)
#Receiver各层菜单
receiverMenu.ApplicationLayer = Menu(receiverMenu, tearoff=0)
receiverMenu.TransportLayer = Menu(receiverMenu, tearoff=0)
receiverMenu.NetworkLayer = Menu(receiverMenu, tearoff=0)
receiverMenu.LinkLayer = Menu(receiverMenu, tearoff=0)
receiverMenu.PhysicalLayer = Menu(receiverMenu, tearoff=0)
#Receiver添加各层菜单
receiverMenu.add_cascade(label='应用层', menu=receiverMenu.ApplicationLayer)
receiverMenu.add_separator()
receiverMenu.add_cascade(label='传输层', menu=receiverMenu.TransportLayer)
receiverMenu.add_separator()
receiverMenu.add_cascade(label='网络层', menu=receiverMenu.NetworkLayer)
receiverMenu.add_separator()
receiverMenu.add_cascade(label='链路层', menu=receiverMenu.LinkLayer)
receiverMenu.add_separator()
receiverMenu.add_cascade(label='物理层', menu=receiverMenu.PhysicalLayer)
mainMenu.add_cascade(label="  接收方  ", menu=receiverMenu)

#解包分析部分
Frame(
    root,
    height=root.winfo_screenheight() / 2 - 15,
    width=root.winfo_screenwidth(),
    bg='gray').grid(
        row=0, column=0, sticky=W + N)
Frame(
    root,
    height=root.winfo_screenheight() / 2 - 21,
    width=root.winfo_screenwidth(),
    bg='BurlyWood').grid(
        row=0, column=0, sticky=W + N)

analysisText = ScrolledText(
    root, width=149, height=18, font=('Consolas', 13), fg='black', bg='white')
analysisText.grid(row=0, column=0, sticky=W + N, padx=6)
#数据部分
Frame2 = Frame(
    root,
    height=root.winfo_screenheight() / 4,
    width=root.winfo_screenwidth(),
    bg='gray')
Frame2.grid(row=1, column=0)

dataText = ScrolledText(
    Frame2,
    width=149,
    height=10,
    font=('Consolas', 13),
    fg='black',
    bg='white')
dataText.grid(row=1, column=0, sticky=W, padx=5, columnspan=3)

#输入部分
Frame3 = Frame(
    root,
    height=root.winfo_screenheight() / 8 + 20,
    width=root.winfo_screenwidth(),
    bg='gray')
Frame3.grid(row=2, column=0, sticky=W)
Button(
    root, text=' Send ', command=packingData, height=2, width=13).grid(
        row=2, column=0, sticky=E, padx=40)

inputData = Text(root, width=160, height=4)
inputData.grid(row=2, column=0, sticky=W, padx=60)

inputData.bind("<Control-Key-a>", selectText)
inputData.bind("<Control-Key-A>", selectText)

root.geometry("%dx%d" % (root.winfo_screenwidth() - 5,
                         root.winfo_screenheight()))
root.config(menu=mainMenu)
root.mainloop()
