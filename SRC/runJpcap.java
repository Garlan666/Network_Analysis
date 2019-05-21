package 流量分析;

import javax.swing.DefaultListModel;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class runJpcap{
	public NetworkInterface[] devices;
public runJpcap() {
	getDevices();
}

//获取网络接口列表
public void getDevices() {
	devices = JpcapCaptor.getDeviceList();
	DefaultListModel<String> dlm = new DefaultListModel<String>();
	for (int i = 0; i < devices.length; i++) {
		 dlm.addElement("网卡"+i+":"+devices[i].description);
		}
	Main.list.setModel(dlm);
	}


}
