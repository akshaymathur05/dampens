# -*- coding: utf-8 -*-
"""
Created on Tue May 24 15:47:56 2022

@author: aksha
"""

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from __future__ import division
from scapy.all import*
import sys
from scapy.layers import http
from decimal import *
from time import sleep
from decimal import Decimal
import os
from os import listdir
from os.path import isfile, join
from collections import namedtuple



tuf=namedtuple("TCPUDP",['proto', 'src', 'dst', 'sp', 'dp'])

ptf = (6,'','',0,0)# previous TCP flow
ptt = 0.0# previous TCP packet time
puf = (17,'','',0,0)# previous UDP flow
put = 0.0# previous UDP packet time

line="apkNum"+","+"totalPkts"+","+"totalPktSize"+","+"totalDnsPkts"+","+"totalHttpPkts"+","+"totalHttpsPkts"+","+"totalTcpPkts"+","+"totalUdpPkts"+","+"totalPktsIn"+","+"totalBytesIn"+","+"totalPktsOut"+","+"totalBytesOut"+","+"PktSizeRatio"+","+"medPktsIn"+","+"medPktsOut"+","+"avgPktsIn"+","+"avgPktsOut"+","+"avgPktSize"+","+"maxOutPktSize"+","+"maxInPktSize"+","+"ratioNumPkts"+","+"minTimeOut"+","+"minTimeIn"+","+"avgNumpktFlowTCPIn"+","+"avgNumpktFlowUDPIn"+","+"avgSizepktFlowTCPIn"+","+"avgSizepktFlowUDPIn"+","+"avgNumpktFlowTCPOut"+","+"avgNumpktFlowUDPOut"+","+"avgSizepktFlowTCPOut"+","+"avgSizepktFlowUDPOut"+","+"Result"+"\n"


'''#make directory changes. Make it universal'''

#onlyfiles = [f for f in listdir('/home/safia/drebinDataset/DatasetsFOrFlowAnalysis/traditionalBenign') if isfile(join('/home/safia/drebinDataset/DatasetsFOrFlowAnalysis/traditionalBenign', f))]
#onlyfiles = [f for f in listdir('C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp4\\azoo_pcaps') if isfile(join('C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp4\\azoo_pcaps', f))]
#onlyfiles = [f for f in listdir('D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\malicious') if isfile(join('D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\malicious', f))]
onlyfiles = [f for f in listdir('D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\filtered_malicious') if isfile(join('D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\filtered_malicious', f))]

#onlyfiles = [f for f in listdir('D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\benign\\') if isfile(join('D:\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\benign\\', f))]

#onlyfiles = [f for f in listdir('C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\benign\\') if isfile(join('C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\benign\\', f))]

print("got filenames", len(onlyfiles))
#target = open('/home/safia/drebinDataset/DatasetsFOrFlowAnalysis/traditionalBenign/dataset/labeledDatasetben2.csv','a')
#target = open('C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\benign_ntd.csv','a')
#target = 'D:\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\benign_ntd.csv'
#target = 'D:\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\malicious_ntd.csv'
target = 'D:\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\filtered_malicious_ntd.csv'


if os.path.exists(target) == True and os.stat(target).st_size != 0:
    target = open(target,'a')
else:
    target = open(target,'a')    
    target.write(line)

#len(onlyfiles)
print("opened targetDoc")
for i in range(len(onlyfiles)):
	print("\n\n\n\nreading pcap", onlyfiles[i],i)
	a=rdpcap('D:\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\pcaps\\filtered_malicious\\'+onlyfiles[i])
	print("read pcap new")
	inpkt=0
	inbyte=0
	outbyte=0
	bytesSec=0
	dnsPkt=0
	ratio=0
	httpPkt=0
	ratioNum=0
	summ=0
	tcp=0
	udp=0
	dhcp=0
	https=0
	arrBytesSec=[]
	outpkt=0

	t=a[0].time
	print("start time",t)
	#sleep(2)
	totalPkt=0
	#new parameters
	numPkts=[] #num of pkt per minute
	incomingPkt=[] # num of pkts coming per minute
	outgoingPkt=[] # num of pkts going per minute
	byteMin=[] # size per minute
	byteIn=[]#size of incoming pkt
	byteOut=[] #size of outgoing pkt
	protocol={}   # protocol-wise count
	httpFeatures={}
	httpPktCount=[]
	dnsPktCount=[]
	inOutRatio=[]
	dhcpPktCount=[]
	tcpCount=[]
	udpCount=[]
	dports={}
	sports={}
	listOfIPsSrc=[]
	listOfIPsDst=[]
	dstPorts=[]
	srcPorts=[]
	srcPort=0
	dstPort=0
	cntTcpFlowIn=0
	cntTcpFlowOut=0

	numPktFlowInTCP=1
	sizePktFlowInTCP=1
	numPktFlowOutTCP=1
	sizePktFlowOutTCP=1
	numPktFlowInUDP=1
	sizePktFlowInUDP=1
	numPktFlowOutUDP=1
	sizePktFlowOutUDP=1


	cntUdpFlowIn=0
	cntUdpFlowOut=0
	numTcpFlow=0
	numUdpFlow=0
	sample=1
	ratio=0
	medianInList=[]
	medianOutList=[]
	timeIn=[]
	timeOut=[]
	line=""
    #http=a.filter(lambda(s):HTTPRequest in s or HTTPResponse in s)
	#print(http.summary())
	for p in a:
		try:
			if p.haslayer("HTTPRequest"):
				method=str(p.Method)
				path=str(p.Path)
				host=str(p.Host)
				if method not in httpFeatures:
					httpFeatures[method]=1
				else:
					httpFeatures[method]+=1
				if path not in httpFeatures:
					httpFeatures[path]=1
				else:
					httpFeatures[path]+=1
				if host not in httpFeatures:
					httpFeatures[host]=1
				else:
					httpFeatures[host]+=1
				#gathering protocols
			if p.proto not in protocol:
				protocol[p.proto]=1
			else:
				protocol[p.proto]+=1

			#distinct src ports
			if p.sport not in sports:
				sports[p.sport]=1
			else:
				sports[p.sport]+=1

			#distict dst ports
			if p.dport not in dports:
				dports[p.dport]=1
			else:
				dports[p.dport]+=1
			#print("ports",p.sport, p.dport,"time", (p.time-t))
			#sleep(1)
            
			if (p.time-t) <=60.0:

				print("here i am in first if")
				#sleep(3)
				if p.sport > 1023 and p[IP].src not in listOfIPsSrc:
					listOfIPsSrc.append(p[IP].src)
				if p.dport > 1023 and p[IP].dst not in listOfIPsDst:
					listOfIPsDst.append(p[IP].dst)
			#print(listOfIPsSrc,listOfIPsDst)
			#sleep(1)
			#print(p.time-t) <=60.0 and ((p[IP].src in listOfIPsSrc) or( p[IP].dst in listOfIPsDst))
			#sleep(5)
			if (p.time-t) <=60.0 and ((p[IP].src in listOfIPsSrc) or( p[IP].dst in listOfIPsDst)):
				print("here i am in second if")
				#sleep(3)
				if p[IP].proto == 6:
					f = tuf(6, p[IP].src, p[IP].dst, p[IP].sport, p[IP].dport)
					print('f',f)
					print('ptf',ptf)
					#sleep(3)
					if f != ptf and p.time != ptt:
						print("i hate this in if")
						#sleep(3)
						ptf = f 
						ptt=p.time
						numTcpFlow+=1
						if p[IP].src in listOfIPsSrc:
							cntTcpFlowIn+=1

						if p[IP].dst in listOfIPsDst:
							cntTcpFlowOut+=1

					else:
						print("i hate this in else")
						#sleep(3)
						if p[IP].src in listOfIPsSrc:
							numPktFlowInTCP+=1
							sizePktFlowInTCP+=p[IP].len
							print("tcp src",numPktFlowInTCP,sizePktFlowInTCP)
							#sleep(3)
						if p[IP].dst in listOfIPsDst:
							numPktFlowOutTCP+=1
							sizePktFlowOutTCP+=p[IP].len
							print("tcp dst",numPktFlowOutTCP,sizePktFlowOutTCP)
							#sleep(3)
				elif p[IP].proto == 17:
					f = tuf(17, p[IP].src, p[IP].dst, p[IP].sport, p[IP].dport)
					if not (f == puf and p.time == put):
						puf = f 
						put = p.time
						numUdpFlow+=1
						if p[IP].src in listOfIPsSrc:
							cntUdpFlowIn+=1

						if p[IP].dst in listOfIPsDst:
							cntUdpFlowOut+=1

					else:
						if p[IP].src in listOfIPsSrc:
							numPktFlowInUDP+=1
							sizePktFlowInUDP+=p[IP].len
						if p[IP].dst in listOfIPsDst:
							numPktFlowOutUDP+=1
							sizePktFlowOutUDP+=p[IP].len
				#print("here")
				#print("i am in feature loop")
				#sleep(1)
				# gathering bytes
				print("here i am out of if")
				#sleep(3)
				totalPkt+=1
				#print("total packets",p.time-t,totalPkt)
				#sleep(1)
				bytesSec+=p[IP].len
				# gathering HTTP features
				if p.sport not in srcPorts:
					srcPort+=1
				if p.dport not in dstPorts:
					dstPort+=1
				if p.haslayer("DNS"):
					dnsPkt+=1
				if p.haslayer("HTTPRequest"):
					httpPkt+=1
				if p.haslayer("DHCP"):
					dhcp+=1
				#gathering protocols
				if p[IP].proto == 6:
					tcp+=1
					print("tcp", tcp)
					#sleep(3)
				if p[IP].proto == 17:
					udp+=1
				if p[IP].proto==443:
						https+=1
				

				if p[IP].src in listOfIPsSrc:
					inpkt+=1   #num of incoming packets
					inbyte+=p[IP].len # size of outgoing packets
					medianInList.append(p[IP].len)
					intime=round((p.time-t),2)
					timeIn.append(intime)#new
					
				if p[IP].dst in listOfIPsDst:
					outpkt+=1 #num of outgoing packets
					outbyte+=p[IP].len #size of incoming packets
					medianOutList.append(p[IP].len)
					outtime=round((p.time-t),2)
					timeOut.append(outtime)#new


				ratioNum=float(inpkt)/float(outpkt)
				#ratio=float(inbyte)/float(outbyte)
				#ratio=round(ratio,2)
				#print(ratio)
				ratioNum=round(ratioNum,2)

			else:
				# change last attribute to 0 if benign and 1 if malicious.
				if totalPkt >0:
					try:
						timeIn.sort()
						minTimeIn=timeIn[0]# min time interval between packet sent
						minTimeIn=round(minTimeIn,2)
						timeOut.sort()
						minTimeOut=timeOut[0] #min time interval between packet received
						minTimeOut=round(minTimeOut,2)
						avgIn=float(inbyte)/float(inpkt)
						avgIn=round(avgIn,2)
						#print(avgIn)
						ratio=float(outbyte)/float(inbyte)
						ratio=round(ratio,2)
						print(outpkt,outbyte)
						ratioNum=float(inpkt)/float(outpkt)
						ratioNum=round(ratioNum,2)
						avgOut=float(outbyte)/float(outpkt)
						avgOut=round(avgOut,2)
						avgTotal=float(totalPkt)/float(bytesSec)#new
						avgTotal=round(avgTotal,2)

						avgNumpktFlowTCPIn=float(numPktFlowInTCP)/float(numTcpFlow)
						avgSizepktFlowTCPIn=float(sizePktFlowInTCP)/float(numTcpFlow)
						avgSizepktFlowTCPIn=round(avgSizepktFlowTCPIn,2)
						avgNumpktFlowTCPOut=float(numPktFlowOutTCP)/float(numTcpFlow)
						avgNumpktFlowTCPOut=round(avgNumpktFlowTCPOut,2)
						avgNumpktFlowTCPIn=round(avgNumpktFlowTCPIn,2)
						avgSizepktFlowTCPOut=float(sizePktFlowOutTCP)/float(numTcpFlow)
						avgSizepktFlowTCPOut=round(avgSizepktFlowTCPOut,2)

						avgNumpktFlowUDPIn=float(numPktFlowInUDP)/float(numUdpFlow)
						avgNumpktFlowUDPIn=round(avgNumpktFlowUDPIn,2)
						avgSizepktFlowUDPIn=float(sizePktFlowInUDP)/float(numUdpFlow)
						avgSizepktFlowUDPIn=round(avgSizepktFlowUDPIn,2)

						avgNumpktFlowUDPOut=float(numPktFlowOutUDP)/float(numUdpFlow)
						avgNumpktFlowUDPOut=round(avgNumpktFlowUDPOut,2)
						avgSizepktFlowUDPOut=float(sizePktFlowOutUDP)/float(numUdpFlow)
						avgSizepktFlowUDPOut=round(avgSizepktFlowUDPOut,2)
					except:
						pass

					medianInList.sort()
					maxOutSize=medianInList[len(medianInList)-1]
					if len(medianInList)%2==0:
						midIn=int(len(medianInList)/2)
						medianIn=(medianInList[midIn]+medianInList[midIn+1])/2
					if len(medianInList)%2!=0:
						midIn=int(len(medianInList)/2)
						medianIn=medianInList[midIn]

					medianOutList.sort()
					maxInSize=medianOutList[len(medianOutList)-1]
					if len(medianOutList)%2==0:
						midOut=int(len(medianOutList)/2)
						medianOut=(medianOutList[midOut]+medianOutList[midOut+1])/2
					if len(medianOutList)%2!=0:
						midOut=int(len(medianOutList)/2)
						medianOut=medianOutList[midOut]

					#sleep(10)

					line=str(onlyfiles[i])+","+str(totalPkt)+","+str(bytesSec)+","+str(dnsPkt)+","+str(httpPkt)+","+str(https)+","+str(tcp)+","+str(udp)+","+str(inpkt)+","+str(inbyte)+","+str(outpkt)+","+str(outbyte)+","+str(ratio)+","+ str(medianIn)+","+str(medianOut)+","+str(avgIn)+","+str(avgOut)+","+str(avgTotal)+","+str(maxOutSize)+","+str(maxInSize)+","+str(ratioNum)+","+str(minTimeOut)+","+str(minTimeIn)+","+str(avgNumpktFlowTCPIn)+","+str(avgNumpktFlowUDPIn)+","+str(avgSizepktFlowTCPIn)+","+str(avgSizepktFlowUDPIn)+","+str(avgNumpktFlowTCPOut)+","+str(avgNumpktFlowUDPOut)+","+str(avgSizepktFlowTCPOut)+","+str(avgSizepktFlowUDPOut)+","+str(1)

                    #line=str(onlyfiles[i])+","+str(totalPkt)+","+str(bytesSec)+","+str(dnsPkt)+","+str(httpPkt)+","+str(https)+","+str(tcp)+","+str(udp)+","+str(inpkt)+","+str(inbyte)+","+str(outpkt)+","+str(outbyte)+","+str(ratio)+","+ str(medianIn)+","+str(medianOut)+","+str(avgIn)+","+str(avgOut)+","+str(avgTotal)+","+str(maxOutSize)+","+str(maxInSize)+","+str(ratioNum)+","+str(minTimeOut)+","+str(minTimeIn)+","+str(avgNumpktFlowTCPIn)+","+str(avgNumpktFlowUDPIn)+","+str(avgSizepktFlowTCPIn)+","+str(avgSizepktFlowUDPIn)+","+str(avgNumpktFlowTCPOut)+","+str(avgNumpktFlowUDPOut)+","+str(avgSizepktFlowTCPOut)+","+str(avgSizepktFlowUDPOut)+","+str(0)

					target.write(line+'\n')
					t=p.time
					#print("time",t)
					#sleep(5)
					#print("total packets in a minute",totalPkt)
					line=""
					tcpCount.append(tcp)
					udpCount.append(udp)
					dhcpPktCount.append(dhcp)
					httpPktCount.append(httpPkt)
					dnsPktCount.append(dnsPkt)
					numPkts.append(totalPkt)
					totalPkt=1
					incomingPkt.append(inpkt)
					inpkt=0
					outgoingPkt.append(outpkt)
					outpkt=0
					byteMin.append(bytesSec)
					bytesSec=p[IP].len
					ratioNum=0
					inOutRatio.append(ratio)
					ratio=0
					byteIn.append(inbyte)
					inbyte=0
					byteOut.append(outbyte)
					outbyte=0
					dnsPkt=0
					httpPkt=0
					dhcp=0
					https=0
					srcPort=0
					dstPort=0

					numPktFlowInTCP=1
					sizePktFlowInTCP=1
					numPktFlowOutTCP=1
					sizePktFlowOutTCP=1
					numPktFlowInUDP=1
					sizePktFlowInUDP=1
					numPktFlowOutUDP=1
					sizePktFlowOutUDP=1

					cntTcpFlowIn=0
					cntTcpFlowOut=0
					cntUdpFlowIn=0
					cntUdpFlowOut=0
					numTcpFlow=0
					numUdpFlow=0
					listOfIPsSrc=[]
					listOfIPsDst=[]
					medianInList=[]
					medianOutList=[]
					timeIn=[]
					timeOut=[]
					if p[IP].proto==6:
						tcp=1
					if p[IP].proto==17:
						udp=1
					if p.haslayer("DNS"):
						dnsPkt=1
					if p.haslayer("HTTPRequest"):
						httpPkt=1
					if p.haslayer("DHCP"):
						dhcp=1
					if p[IP].src in listOfIPs:
						inpkt=1   #num of incoming packets
						inbyte=p[IP].len # size of incoming packets
						medianInList.append(p[IP].len)
					if p[IP].dst in listOfIPs:
						outpkt=1 #num of outgoing packets
						outbyte=p[IP].len #size of outgoing packets
					listOfIPs=[]
					
					

		except:
			pass
	print("num of tcp pkts",tcpCount)
	print("num of udp pkts",udpCount)
	print("num of udp pkts",httpPktCount)
	print("num of dns pkts",dnsPktCount)
	print("num of dhcp pkts",dhcpPktCount)

	print("num of pkts",numPkts)
	print("incoming num of pkts",incomingPkt)
	print("outgoing num of pkts",outgoingPkt)
	print("total size of pkts",byteMin)
	print("size of incoming pkts",byteIn)
	print("size of outgoing pkts",byteOut)
	print("ratio of incoming to outgoing bytes",inOutRatio)
	print("protocols", protocol)
	#print("distint src ports and their count", sports)
	#print("distint dst ports and their count", dports)
	#print("httpFeatures", httpFeatures)
target.close()
print("closed targetDoc")

'''

avgInpkt=int(inbyte/inpkt)
avgOutPkt=int(outbyte/outpkt)
print(a)
print("incoming packets: ",inpkt,"outgoing packets: ",outpkt)
print("incoming bytes: ",inbyte,"outgoing bytes: ",outbyte)
print("average size of incoming pkts: ",avgInpkt,"average size of outgoing pkts: ",avgOutPkt)
print("total num of pkt: ",len(a),"num of tcp pkt: ",tcp,"num of udp pkts: ",udp)
for i in arrBytesSec:
	summ+=i
avgByteSec=summ/len(arrBytesSec)
print("avg number of bytes received per second: ", avgByteSec)
'''

