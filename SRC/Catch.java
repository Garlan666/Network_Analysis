package 流量分析;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
//用于获取，分析，过滤数据包
public class Catch{
public static ArrayList<myPacket> pacList=new ArrayList<myPacket>();
public static int counter=0;
static SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
Packet packet;static String src="";
static String dst="";
static String pro="";
static String srcPort="";
static String dstPort="";
public static int[]cons= {0,0,0,0,0,0,0,0};
public static boolean flag=false; 
public static boolean end=true;
NetworkInterface Interface;
public Catch(int index) throws IOException {
	NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	Interface=devices[index];
	JpcapCaptor captor = JpcapCaptor.openDevice(devices[index], 65535, false, 40);
	 catchPackets.table.addMouseListener(new MouseAdapter(){
		  @Override
		  public void mouseClicked(MouseEvent e) {//绑定表格点击事件
		   if(e.getClickCount()==1){
			    int index=catchPackets.table.getSelectedRow();
		        index=Integer.parseInt(catchPackets.table.getValueAt(index, 0).toString());
	    		analysis(index);
	    		frameAna(index);
		   }
		  }        
		 });
	    
		while (catchPackets.start) {
		packet = captor.getPacket();	//获取数据包
		if (packet != null) {
			myPacket mp=new myPacket();
			mp.network= Interface.name + "(" + Interface.description + ")";
			mp.dataline= Interface.datalink_name + "(" + Interface.datalink_description + ")";
			mp.usec = System.currentTimeMillis();
			mp.len=packet.len;
			mp.head=packet.header;
			mp.data=packet.data;
			byte[]e=packet.header;
			byte[]f=new byte[12];
			byte[]g=new byte[2];
			System.arraycopy(e, 0, f, 0, 12);
			System.arraycopy(e, 12, g, 0, 2);
			String mac=BytesToHexString(f);String ver=BytesToHexString(g);
			String m=mac.substring(0,2);
			for(int i=2;i<12;i=i+2) {
				m+=":"+mac.substring(i,i+2);
			}
			mp.macd=m;
			m=mac.substring(12, 14);
			for(int i=14;i<24;i=i+2) {
				m+=":"+mac.substring(i,i+2);
			}
			mp.macs=m;
			mp.ver0x="0x"+ver;
			if(ver.equals("0800")) {
				mp.ver="ipv4";
			}
			else if(ver.equals("86dd")) {
				mp.ver="ipv6";
			}
			else if(ver.equals("0806")) {
				mp.ver="ARP";
			}
			else {
				mp.ver="unknow";
			}
			//判断数据包类型
			if(packet instanceof jpcap.packet.TCPPacket) {
				
				 TCPPacket p=(TCPPacket)packet;
				 src=p.src_ip.toString();src=src.substring(1);
				 dst=p.dst_ip.toString();dst=dst.substring(1);
				 srcPort=""+p.src_port;
				 dstPort=""+p.dst_port;
				 pro="TCP";
				 byte[]b=packet.data;
				 if(b.length>4) {
				 byte[]c=new byte[4];
				 System.arraycopy(b, 0, c, 0, 4);			 
				 String s=BytesToHexString(c);
				 if(s.equals("48545450")||s.equals("47455420")) {
					pro="HTTP" ;
					cons[2]++;
				 }
				 else {
					 cons[0]++;
				 }
				 } 
				 else
				 { 
					 cons[0]++;
				 }
			}
			else if(packet instanceof jpcap.packet.UDPPacket) {
				 UDPPacket p=(UDPPacket)packet;
				 src=p.src_ip.toString();src=src.substring(1);
				 dst=p.dst_ip.toString();dst=dst.substring(1);
				 srcPort=""+p.src_port;
				 dstPort=""+p.dst_port;
				 pro="UDP";
				 cons[1]++;
			}
			else if(packet instanceof jpcap.packet.ARPPacket) {
				 ARPPacket p=(ARPPacket)packet;    
		         src=p.getSenderHardwareAddress().toString(); 
		         dst=p.getTargetHardwareAddress().toString();
		         srcPort="";
		         dstPort="";
		         pro="ARP";
		         cons[3]++;
			}
			else if(packet instanceof jpcap.packet.ICMPPacket) {
				 ICMPPacket p=(ICMPPacket)packet;    
				 src=p.src_ip.toString();src=src.substring(1);
				 dst=p.dst_ip.toString();dst=dst.substring(1);
				 srcPort="";
		         dstPort="";
				 pro="ICMP";
				 cons[4]++;
			}
			else if(packet instanceof jpcap.packet.IPPacket) {
				 IPPacket p=(IPPacket)packet;
				 src=p.src_ip.toString();src=src.substring(1);
				 dst=p.dst_ip.toString();dst=dst.substring(1);
				 srcPort="";
		         dstPort="";
				 pro="ipv4";
				 cons[5]++;
			}
		    else {
				 src=mp.macs;
				 dst=mp.macd;
				 srcPort="";
		         dstPort="";
		         if(mp.ver.equals("ipv6"))
		         { 
		        	 pro="ipv6";
		             cons[6]++;
		         }	 
		         else pro="Other";
				 cons[7]++;
			}
		 	String s=catchPackets.text;
		 	String s1="",s2=s;
		 	s = s.replaceAll("num",""+counter);
		 	s = s.replaceAll("pro",'"'+pro+'"');
			s = s.replaceAll("src",'"'+src+'"');
			s = s.replaceAll("dst",'"'+dst+'"');
			s = s.replaceAll("sp",'"'+srcPort+'"');
			s = s.replaceAll("dp",'"'+dstPort+'"');
			s = s.replaceAll("len",""+packet.len);
			for(int i1=0;i1<s2.length();i1++)
			{
				if(s2.charAt(i1)=='a')
				{
					s=s.replaceFirst("a\\(", "1>");
					i1+=2;
					while(i1<s2.length()&&s2.charAt(i1)!=')')
					{
					s1+=s2.charAt(i1++);
					}
				}
				if(s2.charAt(i1)=='b')
				{
					s=s.replaceFirst("b\\(","1<");
					i1+=2;
					while(i1<s2.length()&&s2.charAt(i1)!=')')
					{
					s1+=s2.charAt(i1++);
					}
				}
				Date t=null;
				if(s1!="")
				{
					try {
					t=(Date) df.parse(s1);
					} catch (ParseException e1) {
					e1.printStackTrace();
					}
				}
				if(t!=null&&s1!="")
					{
					Long l=t.getTime();Long r=mp.usec;
					if(l.compareTo(r)==-1)s=s.replaceFirst(s1+"\\)","0");
					else if(l.compareTo(r)==0)s=s.replaceFirst(s1+"\\)","1");
					else if(l.compareTo(r)==1)s=s.replaceFirst(s1+"\\)","2");		
					
					}
			}
			
			try {
				if(end&&(s.equals("")||s.equals("")==false&&sfilter(s)==true))
				{
					catchPackets.tab.addRow(new String[]{""+counter,""+df.format(mp.usec),src,srcPort,dst,dstPort,pro,""+mp.len});	
				}
			} catch (ScriptException e1) {
				e1.printStackTrace();
			}
			mp.pro=pro;
		 	mp.src=src;mp.dst=dst;
		 	if(!srcPort.equals(""))mp.srcPort=Integer.parseInt(srcPort);
		 	if(!dstPort.equals(""))mp.dstPort=Integer.parseInt(dstPort);
		 	pacList.add(counter, mp);
		 	counter++;
		 	if(flag) {
		 		Analysis.redraw(cons);
		 		}
		 	}
		}
}
//重载构造函数，用于展示历史记录
public Catch(ArrayList<myPacket> ap) {
	catchPackets.table.addMouseListener(new MouseAdapter(){
		  @Override
		  public void mouseClicked(MouseEvent e) {
		   if(e.getClickCount()==1){
			    int index=catchPackets.table.getSelectedRow();
		        index=Integer.parseInt(catchPackets.table.getValueAt(index, 0).toString());
	    		analysis(index);
	    		frameAna(index);
		   }
		  }        
		 });
	
	pacList=ap;
	counter=pacList.size();
	myPacket mp;
	for(int i=0;i<counter;i++) {
		mp=pacList.get(i);
		String srcport="",dstport="";
		if(mp.srcPort!=0)srcport=""+mp.srcPort;
		if(mp.dstPort!=0)dstport=""+mp.dstPort;
		catchPackets.tab.addRow(new String[]{""+i,""+df.format(mp.usec),mp.src,""+srcport,mp.dst,""+dstport,mp.pro,""+mp.len});
	}
	
	
}

public static void fil() throws ScriptException
{
	String s=catchPackets.text;
	String s2=s,s1="";
	catchPackets.tab.setRowCount( 0 );
	for(int i=0;i<counter;i++)
	{
		s=s2;s1="";
		myPacket packet=pacList.get(i);
		s = s.replaceAll("num",""+i);
		s = s.replaceAll("pro",'"'+packet.pro+'"');
		s = s.replaceAll("src",'"'+packet.src+'"');
		s = s.replaceAll("dst",'"'+packet.dst+'"');
		s = s.replaceAll("sp",'"'+""+packet.srcPort+'"');
		s = s.replaceAll("dp",'"'+""+packet.dstPort+'"');
		s = s.replaceAll("len",""+packet.len);	
		for(int i1=0;i1<s2.length();i1++)
		{
			if(s2.charAt(i1)=='a')
			{
				s=s.replaceFirst("a\\(", "1>");
				i1+=2;
				while(i1<s2.length()&&s2.charAt(i1)!=')')
				{
				s1+=s2.charAt(i1++);
				}
			}
			if(s2.charAt(i1)=='b')
			{
				s=s.replaceFirst("b\\(","1<");
				i1+=2;
				while(i1<s2.length()&&s2.charAt(i1)!=')')
				{
				s1+=s2.charAt(i1++);
				}
			}
			Date t=null;
			if(s1!="")
			{
				try {
				t=(Date) df.parse(s1);
				} catch (ParseException e1) {
				e1.printStackTrace();
				}
			}
			if(t!=null&&s1!="")
				{
				Long l=t.getTime();Long r=packet.usec;
				if(l.compareTo(r)==-1)s=s.replaceFirst(s1+"\\)","0");
				else if(l.compareTo(r)==0)s=s.replaceFirst(s1+"\\)","1");
				else if(l.compareTo(r)==1)s=s.replaceFirst(s1+"\\)","2");		
				}
		}
		if(s.equals("")==false&&sfilter(s)==true||s.equals(""))
		{
			String srcport="",dstport="";
			if(packet.srcPort!=0)srcport=""+packet.srcPort;
			if(packet.dstPort!=0)dstport=""+packet.dstPort;
			catchPackets.tab.addRow(new String[]{""+i,""+df.format(packet.usec),packet.src,srcport,packet.dst,dstport,packet.pro,""+packet.len});	
		}
	}
	end=true;

}

//获取16进制
public String BytesToHexString(byte[]b)
{
	 StringBuilder buf = new StringBuilder(b.length * 2);
     for(byte a : b)
     { // 使用String的format方法进行转换
         buf.append(String.format("%02x", new Integer(a & 0xff)));
     }
     return buf.toString();
} 
//16进制转字符
public String hexStringToString(String string)
{
	String sub = "";int data=0;
	for (int i = 0; i < string.length() / 2; i++)
	{
		data= Integer.valueOf(string.substring(i * 2, i * 2 + 2),16).byteValue();
		if(data>0x20&&data<0x7f) 
		{//提取可显示字符
		sub = sub + (char)data;
		} 
		else sub=sub+"..";
    }  
	return sub;
	}
//byte转bit
public int[] byteTobits(String B) {
	int []bits;
	switch(B) {
	case "0":bits= new int []{0,0,0,0};break;
	case "1":bits= new int []{0,0,0,1};break;
	case "2":bits= new int []{0,0,1,0};break;
	case "3":bits= new int []{0,0,1,1};break;
	case "4":bits= new int []{0,1,0,0};break;
	case "5":bits= new int []{0,1,0,1};break;
	case "6":bits= new int []{0,1,1,0};break;
	case "7":bits= new int []{0,1,1,1};break;
	case "8":bits= new int []{1,0,0,0};break;
	case "9":bits= new int []{1,0,0,1};break;
	case "a":
	case "A":bits= new int []{1,0,1,0};break;
	case "b":
	case "B":bits= new int []{1,0,1,1};break;
	case "c":
	case "C":bits= new int []{1,1,0,0};break;
	case "d":
	case "D":bits= new int []{1,1,0,1};break;
	case "e":
	case "E":bits= new int []{1,1,1,0};break;
	default:bits=new int[] {1,1,1,1};break;
	}
	return bits;
}
//16进制字符转10进制数字
public int Hexto10(String he) {
	int ten=0;int two=1;
	int len=he.length();
	int []temp;
	for(int i=len;i>0;i--) {
		temp= byteTobits(he.substring(i-1, i));
		for(int t=3;t>=0;t--) {
			ten+=temp[t]*two;
			two*=2;
		}
	}
	return ten;
}
//展开数据包
public void analysis(int index) {
	catchPackets.textArea.setText("");
	
	String head=BytesToHexString(pacList.get(index).head);
	int i=0,len=head.length();String dd,ss;
	catchPackets.textArea.append("header:"+"\n");
	for(i=0;i<len-16;i+=16) 
	{
		dd=head.substring(i, i+17);
		ss=hexStringToString(dd);
		catchPackets.textArea.append(dd+"\t"+ss+"\n");
	}
	dd=head.substring(i, len);
	ss=hexStringToString(dd);
	catchPackets.textArea.append(dd+"\t"+ss+"\n");
	
	
	String data=BytesToHexString(pacList.get(index).data);
	i=0;len=data.length();
	catchPackets.textArea.append("data:"+"\n");
	for(i=0;i<len-16;i+=16) 
	{
		dd=data.substring(i, i+17);
		ss=hexStringToString(dd);
		catchPackets.textArea.append(dd+"\t"+ss+"\n");
	}
	dd=data.substring(i, len);
	ss=hexStringToString(dd);
	catchPackets.textArea.append(dd+"\t"+ss+"\n");
}
//过滤框
public static boolean sfilter(String s) throws ScriptException{
	ScriptEngineManager manager = new ScriptEngineManager();
	ScriptEngine se = manager.getEngineByName("JavaScript");  
	boolean result=false;
			result = (Boolean)se.eval(s);
	return result;
}

//数据包分层解析
public void frameAna(int index) {
	myPacket packet=pacList.get(index);byte[]a=packet.head;
	DefaultMutableTreeNode root=new DefaultMutableTreeNode("数据帧："+index);
	DefaultMutableTreeNode r1=new DefaultMutableTreeNode("信息");
	DefaultMutableTreeNode r2=new DefaultMutableTreeNode("数据链路层");
	DefaultMutableTreeNode r3=new DefaultMutableTreeNode("网络层");
	DefaultMutableTreeNode r4=new DefaultMutableTreeNode("传输层");
	root.add(r1);
	root.add(r2);
	
	DefaultMutableTreeNode r1_1=new DefaultMutableTreeNode("网卡： " +packet.network);
	DefaultMutableTreeNode r1_2=new DefaultMutableTreeNode(" datalink: " +packet.dataline);
	DefaultMutableTreeNode r1_3=new DefaultMutableTreeNode("时间："+df.format(packet.usec)+" (北京时间)");
	DefaultMutableTreeNode r1_4=new DefaultMutableTreeNode("大小："+packet.len+"byte"+"("+packet.len*8+"bits)");
	DefaultMutableTreeNode r2_1=new DefaultMutableTreeNode("源地址："+packet.macs);
	DefaultMutableTreeNode r2_2=new DefaultMutableTreeNode("目的地址："+packet.macd);
	DefaultMutableTreeNode r2_3=new DefaultMutableTreeNode("类型："+packet.ver+"("+packet.ver0x+")");
	
	switch(packet.pro) {
	case "TCP":
	case "HTTP":
	    {
	    byte[]b=new byte[1];
	    System.arraycopy(a, 14, b, 0, 1);
	    String vl=BytesToHexString(b);
		String ver=vl.substring(0, 1);
		String len=vl.substring(1,2); 
		int[] bits=byteTobits(ver);
		DefaultMutableTreeNode r3_1=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"版本:"+ver);
		bits=byteTobits(len);
		int headlen=4*(bits[0]*8+bits[1]*4+bits[2]*2+bits[3]*1);
		byte []prohead=new byte[headlen];
		System.arraycopy(a, 14, prohead, 0, headlen);
		String head=BytesToHexString(prohead);
		DefaultMutableTreeNode r3_2=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"头部长度:"+headlen
		+"bytes"+"("+len+")");      
		DefaultMutableTreeNode r3_3=new DefaultMutableTreeNode("Differentiated Services Field: 0x"+head.substring(2, 4));
		DefaultMutableTreeNode r3_4=new DefaultMutableTreeNode("长度:"+Hexto10(head.substring(4, 8)));
		String temp;
		temp=head.substring(8,12);
		DefaultMutableTreeNode r3_5=new DefaultMutableTreeNode("Identification:0x"+temp+"("+Hexto10(temp)+")");
		temp=head.substring(12,16);
		DefaultMutableTreeNode r3_6=new DefaultMutableTreeNode("Flags:0x"+temp);
		temp=head.substring(16,18);
		DefaultMutableTreeNode r3_7=new DefaultMutableTreeNode("Time to live:0x"+temp+"="+Hexto10(temp));
		temp=head.substring(18,20);
		DefaultMutableTreeNode r3_8=new DefaultMutableTreeNode("协议:TCP("+Hexto10(temp)+")");
		temp=head.substring(20,24);
		DefaultMutableTreeNode r3_9=new DefaultMutableTreeNode("头部校验和:0x"+temp);
		DefaultMutableTreeNode r3_10=new DefaultMutableTreeNode("源地址:"+packet.src);
		DefaultMutableTreeNode r3_11=new DefaultMutableTreeNode("目的地址:"+packet.dst);
		byte[]t=new byte[20];
 		System.arraycopy(a, 14+headlen, t, 0, 20);
 		String tcp=BytesToHexString(t);
 		DefaultMutableTreeNode r4_1=new DefaultMutableTreeNode("源端口:"+packet.srcPort);
 		DefaultMutableTreeNode r4_2=new DefaultMutableTreeNode("目的端口:"+packet.dstPort);
		temp=tcp.substring(8, 16);
		DefaultMutableTreeNode r4_3=new DefaultMutableTreeNode("序列号:0x"+temp);
		temp=tcp.substring(16,24);
		DefaultMutableTreeNode r4_4=new DefaultMutableTreeNode("确认号:0x"+temp);
		temp=tcp.substring(24,25);
		DefaultMutableTreeNode r4_5=new DefaultMutableTreeNode("头部长度:"+Integer.parseInt(temp)*4+"("+temp+")");
		temp=tcp.substring(25,28);
		DefaultMutableTreeNode r4_6=new DefaultMutableTreeNode("标志位:0x"+temp);
		int []bit=byteTobits(tcp.substring(25,26));
		DefaultMutableTreeNode r4_6_1=new DefaultMutableTreeNode("Reserved:"+bit[0]+bit[1]+bit[2]);
		DefaultMutableTreeNode r4_6_2=new DefaultMutableTreeNode("Nonce:"+bit[3]);
		bit=byteTobits(tcp.substring(26,27));
		DefaultMutableTreeNode r4_6_3=new DefaultMutableTreeNode("CWR:"+bit[0]);
		DefaultMutableTreeNode r4_6_4=new DefaultMutableTreeNode("ECN-Echo:"+bit[1]);
		DefaultMutableTreeNode r4_6_5=new DefaultMutableTreeNode("Urgent:"+bit[2]);
		DefaultMutableTreeNode r4_6_6=new DefaultMutableTreeNode("Ack:"+bit[3]);
		bit=byteTobits(tcp.substring(27,28));
		DefaultMutableTreeNode r4_6_7=new DefaultMutableTreeNode("Push:"+bit[0]);
		DefaultMutableTreeNode r4_6_8=new DefaultMutableTreeNode("Reset:"+bit[1]);
		DefaultMutableTreeNode r4_6_9=new DefaultMutableTreeNode("Syn:"+bit[2]);
		DefaultMutableTreeNode r4_6_10=new DefaultMutableTreeNode("Fin:"+bit[3]);
		temp=tcp.substring(28,32);
		DefaultMutableTreeNode r4_7=new DefaultMutableTreeNode("窗口大小:0x"+temp+"("+Hexto10(temp)+")");
		temp=tcp.substring(32,36);
		DefaultMutableTreeNode r4_8=new DefaultMutableTreeNode("校验和:0x"+temp);
		
		root.add(r3);
		root.add(r4);
		r3.add(r3_1);
		r3.add(r3_2);
		r3.add(r3_3);
		r3.add(r3_4);
		r3.add(r3_5);
		r3.add(r3_6);
		r3.add(r3_7);
		r3.add(r3_8);
		r3.add(r3_9);
		r3.add(r3_10);
		r3.add(r3_11);
		r4.add(r4_1);
		r4.add(r4_2);
		r4.add(r4_3);
		r4.add(r4_4);
		r4.add(r4_5);
		r4.add(r4_6);
		r4_6.add(r4_6_1);
		r4_6.add(r4_6_2);
		r4_6.add(r4_6_3);
		r4_6.add(r4_6_4);
		r4_6.add(r4_6_5);
		r4_6.add(r4_6_6);
		r4_6.add(r4_6_7);
		r4_6.add(r4_6_8);
		r4_6.add(r4_6_9);
		r4_6.add(r4_6_10);
		r4.add(r4_7);
		r4.add(r4_8);
		if(packet.pro.equals("HTTP")) {
			DefaultMutableTreeNode r5=new DefaultMutableTreeNode("HTTP");
			DefaultMutableTreeNode r5_1=new DefaultMutableTreeNode("长度:"+packet.data.length);
			root.add(r5);
			r5.add(r5_1);
		}
		break;
		}
	case "UDP":
	    {
	    	byte[]b=new byte[1];
	 	    System.arraycopy(a, 14, b, 0, 1);
	 	    String vl=BytesToHexString(b);
	 		String ver=vl.substring(0, 1);
	 		String len=vl.substring(1,2); 
	 		int[] bits=byteTobits(ver);
	 		DefaultMutableTreeNode r3_1=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"版本:"+ver);
	 		bits=byteTobits(len);
	 		int headlen=4*(bits[0]*8+bits[1]*4+bits[2]*2+bits[3]*1);
	 		byte []prohead=new byte[headlen];
	 		System.arraycopy(a, 14, prohead, 0, headlen);
	 		String head=BytesToHexString(prohead);
	 		DefaultMutableTreeNode r3_2=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"头部长度:"+headlen
	 		+"bytes"+"("+len+")");      
	 		DefaultMutableTreeNode r3_3=new DefaultMutableTreeNode("Differentiated Services Field: 0x"+head.substring(2, 4));
	 		DefaultMutableTreeNode r3_4=new DefaultMutableTreeNode("长度:"+Hexto10(head.substring(4, 8)));
	 		String temp;
	 		temp=head.substring(8,12);
	 		DefaultMutableTreeNode r3_5=new DefaultMutableTreeNode("Identification:0x"+temp+"("+Hexto10(temp)+")");
	 		temp=head.substring(12,16);
	 		DefaultMutableTreeNode r3_6=new DefaultMutableTreeNode("Flags:0x"+temp);
	 		temp=head.substring(16,18);
	 		DefaultMutableTreeNode r3_7=new DefaultMutableTreeNode("Time to live:0x"+temp+"="+Hexto10(temp));
	 		temp=head.substring(18,20);
	 		DefaultMutableTreeNode r3_8=new DefaultMutableTreeNode("协议:UDP("+Hexto10(temp)+")");
	 		temp=head.substring(20,24);
	 		DefaultMutableTreeNode r3_9=new DefaultMutableTreeNode("头部校验和:0x"+temp);
	 		DefaultMutableTreeNode r3_10=new DefaultMutableTreeNode("源地址:"+packet.src);
	 		DefaultMutableTreeNode r3_11=new DefaultMutableTreeNode("目的地址:"+packet.dst);
	 		byte[]u=new byte[8];
	 		System.arraycopy(a, 14+headlen, u, 0, 8);
	 		String udp=BytesToHexString(u);
	 		DefaultMutableTreeNode r4_1=new DefaultMutableTreeNode("源端口:"+packet.srcPort);
	 		DefaultMutableTreeNode r4_2=new DefaultMutableTreeNode("目的端口:"+packet.dstPort);
	 		temp=udp.substring(8, 12);
	 		DefaultMutableTreeNode r4_3=new DefaultMutableTreeNode("长度:"+Hexto10(temp));
	 		temp=udp.substring(12,16);
	 		DefaultMutableTreeNode r4_4=new DefaultMutableTreeNode("校验和:0x"+temp);		
	 		DefaultMutableTreeNode r5=new DefaultMutableTreeNode("数据");
	 		DefaultMutableTreeNode r5_1=new DefaultMutableTreeNode("长度:"+packet.data.length);
	 		root.add(r3);
	 		root.add(r4);
	 		root.add(r5);
	 		r3.add(r3_1);
	 		r3.add(r3_2);
	 		r3.add(r3_3);
	 		r3.add(r3_4);
	 		r3.add(r3_5);
	 		r3.add(r3_6);
	 		r3.add(r3_7);
	 		r3.add(r3_8);
	 		r3.add(r3_9);
	 		r3.add(r3_10);
	 		r3.add(r3_11);
	 		r4.add(r4_1);
	 		r4.add(r4_2);
	 		r4.add(r4_3);
	 		r4.add(r4_4);	
	 		r5.add(r5_1);
		break;
		}
	case "ARP":
	    {
	    	DefaultMutableTreeNode r5=new DefaultMutableTreeNode("ARP");
	    	byte[]b=new byte[28];
	    	System.arraycopy(a, 14, b, 0, 28);
	    	String arp=BytesToHexString(b);
	    	String temp=arp.substring(0, 4);
	    	DefaultMutableTreeNode r5_1=new DefaultMutableTreeNode("硬件类型:"+Hexto10(temp));
	    	temp=arp.substring(4,8);
	    	DefaultMutableTreeNode r5_2=new DefaultMutableTreeNode("协议类型:0x"+temp);
	    	temp=arp.substring(8,10);
	    	DefaultMutableTreeNode r5_3=new DefaultMutableTreeNode("硬件大小:"+Hexto10(temp));
	    	temp=arp.substring(10,12);
	    	DefaultMutableTreeNode r5_4=new DefaultMutableTreeNode("协议大小:"+Hexto10(temp));
	    	temp=arp.substring(12,16);
	    	int op=Hexto10(temp);temp="未知";
	    	if(op==1) {
	    		temp="ARP请求";
	    	}
	    	else if(op==2) {
	    		temp="ARP响应";
	    	}
	    	else if(op==3) {
	    		temp="RARP请求";
	    	}
	    	else if(op==4) {
	    		temp="RARP响应";
	    	}
	    	DefaultMutableTreeNode r5_5=new DefaultMutableTreeNode("操作码:"+op+"("+temp+")");
	    	DefaultMutableTreeNode r5_6=new DefaultMutableTreeNode("源MAC地址:"+packet.macs);
	    	DefaultMutableTreeNode r5_7=new DefaultMutableTreeNode("源IP地址:"+Hexto10(arp.substring(28,30))+"."+Hexto10(arp.substring(30,32))
	    	+"."+Hexto10(arp.substring(32,34))+"."+Hexto10(arp.substring(34,36)));
	    	DefaultMutableTreeNode r5_8=new DefaultMutableTreeNode("目的MAC地址:"+packet.macd);
	    	DefaultMutableTreeNode r5_9=new DefaultMutableTreeNode("目的IP地址:"+Hexto10(arp.substring(48,50))+"."+Hexto10(arp.substring(50,52))
	    	+"."+Hexto10(arp.substring(52,54))+"."+Hexto10(arp.substring(54,56)));
	    	
	    	root.add(r5);
	    	r5.add(r5_1);
	    	r5.add(r5_2);
	    	r5.add(r5_3);
	    	r5.add(r5_4);
	    	r5.add(r5_5);
	    	r5.add(r5_6);
	    	r5.add(r5_7);
	    	r5.add(r5_8);
	    	r5.add(r5_9);
		break;
		}
	case "ICMP":
	    {
	    	byte[]b=new byte[1];
	 	    System.arraycopy(a, 14, b, 0, 1);
	 	    String vl=BytesToHexString(b);
	 		String ver=vl.substring(0, 1);
	 		String len=vl.substring(1,2); 
	 		int[] bits=byteTobits(ver);
	 		DefaultMutableTreeNode r3_1=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"版本:"+ver);
	 		bits=byteTobits(len);
	 		int headlen=4*(bits[0]*8+bits[1]*4+bits[2]*2+bits[3]*1);
	 		byte []prohead=new byte[headlen];
	 		System.arraycopy(a, 14, prohead, 0, headlen);
	 		String head=BytesToHexString(prohead);
	 		DefaultMutableTreeNode r3_2=new DefaultMutableTreeNode(""+bits[0]+bits[1]+bits[2]+bits[3]+"="+"头部长度:"+headlen
	 		+"bytes"+"("+len+")");      
	 		DefaultMutableTreeNode r3_3=new DefaultMutableTreeNode("Differentiated Services Field: 0x"+head.substring(2, 4));
	 		DefaultMutableTreeNode r3_4=new DefaultMutableTreeNode("长度:"+Hexto10(head.substring(4, 8)));
	 		String temp;
	 		temp=head.substring(8,12);
	 		DefaultMutableTreeNode r3_5=new DefaultMutableTreeNode("Identification:0x"+temp+"("+Hexto10(temp)+")");
	 		temp=head.substring(12,16);
	 		DefaultMutableTreeNode r3_6=new DefaultMutableTreeNode("Flags:0x"+temp);
	 		temp=head.substring(16,18);
	 		DefaultMutableTreeNode r3_7=new DefaultMutableTreeNode("Time to live:0x"+temp+"="+Hexto10(temp));
	 		temp=head.substring(18,20);
	 		DefaultMutableTreeNode r3_8=new DefaultMutableTreeNode("协议:ICMP("+Hexto10(temp)+")");
	 		temp=head.substring(20,24);
	 		DefaultMutableTreeNode r3_9=new DefaultMutableTreeNode("头部校验和:0x"+temp);
	 		DefaultMutableTreeNode r3_10=new DefaultMutableTreeNode("源地址:"+packet.src);
	 		DefaultMutableTreeNode r3_11=new DefaultMutableTreeNode("目的地址:"+packet.dst);
	 		DefaultMutableTreeNode r5=new DefaultMutableTreeNode("ICMP");	
	 		byte[]c=new byte[4];
	    	System.arraycopy(a, 34, c, 0, 4);
	    	String icmp=BytesToHexString(c);
	    	temp=icmp.substring(0, 2);
	    	DefaultMutableTreeNode r5_1=new DefaultMutableTreeNode("类型:"+Hexto10(temp));
	    	temp=icmp.substring(2,4);
	    	DefaultMutableTreeNode r5_2=new DefaultMutableTreeNode("代码:"+Hexto10(temp));
	    	temp=icmp.substring(4,8);
	    	DefaultMutableTreeNode r5_3=new DefaultMutableTreeNode("校验和:0x"+temp);

	 		root.add(r3);
	 		root.add(r5);
	 		r3.add(r3_1);
	 		r3.add(r3_2);
	 		r3.add(r3_3);
	 		r3.add(r3_4);
	 		r3.add(r3_5);
	 		r3.add(r3_6);
	 		r3.add(r3_7);
	 		r3.add(r3_8);
	 		r3.add(r3_9);
	 		r3.add(r3_10);
	 		r3.add(r3_11);
	 		r5.add(r5_1);
	 		r5.add(r5_2);
	 		r5.add(r5_3);
		break;
		}
	}
	
	r1.add(r1_1);
	r1.add(r1_2);
	r1.add(r1_3);
	r1.add(r1_4);
	r2.add(r2_1);
	r2.add(r2_2);
	r2.add(r2_3);
	
	TreeModel treeModel =new DefaultTreeModel(root);
	catchPackets.tree.setModel(treeModel);
}

}
