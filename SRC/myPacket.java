package 流量分析;

import java.io.Serializable;

public class myPacket implements Serializable {
private static final long serialVersionUID = -3938015712445103193L;
long num=0;
String pro="";
String network="";
String dataline="";
byte[]head=null;
byte[]data=null;
String src="";
String dst="";
int srcPort=0;
int dstPort=0;
long usec=0;
int len=0;
String macs="";
String macd="";
String ver="";
String ver0x="";
}
