package 流量分析;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.Font;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JTextField;
import javax.swing.JTree;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

public class catchPackets extends JFrame{
	private static final long serialVersionUID = -5999340832887709030L;
	public static JTextArea textArea;
	public static JTable table;
	public static DefaultTableModel tab;
	public Catch ca;
	public static JTextField textField;
	public static boolean start=true;
	public static String text="";
	public static JTree tree;
	catchPackets cad=this;
	JPanel jp1=new JPanel();
	public catchPackets(int index) {
		 jp1.setLayout(null); 
		 JButton button = new JButton("停止");
		 button.addMouseListener(new MouseAdapter() {
		 	@Override
		 	public void mouseClicked(MouseEvent e) {
		 		if(button.getText()=="停止")
		 			{
		 			button.setText("继续");
		 			start=false;
					}
		 		else {
		 			Object[] options = {"保存","继续，不保存","取消"};
					int option= JOptionPane.showOptionDialog( 
					catchPackets.this, "继续将重新开始扫描，您是否需要保存已捕获的数据集 ", "提示 ",JOptionPane.YES_NO_CANCEL_OPTION,JOptionPane.QUESTION_MESSAGE, null, options, options[0]); 
					if(option==JOptionPane.YES_OPTION)
					{
						Catch.counter=0;
						String name=""+System.currentTimeMillis();
						JFileChooser chooser = new JFileChooser();
						chooser.setApproveButtonText("保存");
						chooser.setDialogTitle("保存");
						chooser.setCurrentDirectory(new File("D:\\"));
				        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
				        chooser.setSelectedFile(new File(name));
				        chooser.showOpenDialog(null);
				        String path = chooser.getSelectedFile().getPath();
						save(new File(path+".hll"));
						JOptionPane.showMessageDialog(null, "已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
						Catch.pacList=new ArrayList<myPacket>();
						//保存
					}
					if(option==JOptionPane.YES_OPTION||option==JOptionPane.NO_OPTION)
					{
						button.setText("停止");
						Catch.pacList=new ArrayList<myPacket>();
						Catch.counter=0;
						start=true;
						tab.setRowCount( 0 );
						cad.dispose();
						new catchPackets(Main.list.getSelectedIndex());
					} 
					else return;	
		 			}	
		 		
		 	}
		 });
		 button.setBounds(40, 5, 80, 30);
		 jp1.add(button);
		 JButton button_3 = new JButton("历史数据集");
		 button_3.addMouseListener(new MouseAdapter() {
		 	@Override
		 	public void mouseClicked(MouseEvent e) {
		 		JFileChooser chooser = new JFileChooser();
			 	chooser.setCurrentDirectory(new File("D:\\"));
		        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
		        int op=chooser.showDialog(new JLabel(), "选择");
		        File file = chooser.getSelectedFile();
		        if(file!=null&&op==JFileChooser.APPROVE_OPTION) {
		        catchPackets ca=new catchPackets(file);
		   		ca.setVisible(true);
		 	}
		 	}
		 });
		 button_3.setBounds(840, 5, 120, 30);
		 jp1.add(button_3);
		addWindowListener(new WindowAdapter() {
			@Override
				public void windowClosing(WindowEvent e) {
				Object[] options = {"保存并退出","不保存，直接退出","取消"};
				int option= JOptionPane.showOptionDialog( 
				catchPackets.this, "确定退出扫描? ", "提示 ",JOptionPane.YES_NO_CANCEL_OPTION,JOptionPane.QUESTION_MESSAGE, null, options, options[0]); 
				if(option==JOptionPane.YES_OPTION)
				{
					//保存
				    start=false;
					Catch.counter=0;
					String name=""+System.currentTimeMillis();
					JFileChooser chooser = new JFileChooser();
					chooser.setApproveButtonText("保存");
					chooser.setDialogTitle("保存");
					chooser.setCurrentDirectory(new File("D:\\"));
			        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
			        chooser.setSelectedFile(new File(name));
			        chooser.showOpenDialog(null);
			        String path = chooser.getSelectedFile().getPath();
					save(new File(path+".hll"));
					JOptionPane.showMessageDialog(null, "已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
					System.exit(0);
				} 
				else if(option==JOptionPane.NO_OPTION) {
					Catch.counter=0;
					System.exit(0);
					}
				else return;
				}
		});
		setTitle("流量分析");
		setBounds(0, 0, 1920, 1080);
		
		initialize();
		
		new Thread(new Runnable() {
			public void run() {
				try {
				ca =new Catch(index);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}).start();
	}

	
	public catchPackets(File f) {
		jp1.setLayout(null); 
		start=false;
		addWindowListener(new WindowAdapter() {
			@Override
				public void windowClosing(WindowEvent e) {
				cad.dispose();
				} 
		});
		setTitle("流量分析");
		setBounds(0, 0, 1920, 1080);
		
		initialize();
		
		new Thread(new Runnable() {
			public void run() {
				ca = new Catch(load(f));
			}
		}).start();	
	}
	
	private void initialize() {
		 Container container = getContentPane();

		 String []title= {"No","Time","Source","srcPort","Destination","dstPort","Protocol","Length"};
		 table =new JTable();
		 table.setSurrendersFocusOnKeystroke(true);
		 table.setShowVerticalLines(false);
		 table.setShowHorizontalLines(false);
		 table.setShowGrid(false);
		 table.setColumnSelectionAllowed(true);
		 table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		 table.setFont(new Font("宋体", Font.PLAIN, 20));
		 tab=new DefaultTableModel(null,title){
			private static final long serialVersionUID = -7467005391209961797L;
			public boolean isCellEditable(int row,int column) {
		          return false;
		        }
		      };
		 table.setModel(tab);
		 table.setBounds(0, 600, 1890, 322);
		 table.setRowHeight(20);
		 table.setFillsViewportHeight(true);
		 ListSelectionModel selectionMode = table.getSelectionModel();
		 selectionMode.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		 class TableRenderer extends DefaultTableCellRenderer {
			private static final long serialVersionUID = 4841074220318335438L;
			public Component getTableCellRendererComponent(JTable table, Object value,
			     boolean isSelected, boolean hasFocus, int row, int column) {
			    if (column > 0) {
			     super.getTableCellRendererComponent(table, value, isSelected,
			       hasFocus, row, column);
			     return this;
			    }
			    Component cell = super.getTableCellRendererComponent(table, value,
			      isSelected, hasFocus, row, 8);
			    String type=table.getValueAt(row, 6).toString();
			    if(type.equals("TCP")) {
			    	cell.setBackground(Color.green);
			    }
			    else if(type.equals("UDP")) {
			    	cell.setBackground(Color.yellow);
			    }
			    else if(type.equals("ARP")) {
			    	cell.setBackground(Color.orange);
			    }
			    else if(type.equals("ICMP")) {
			    	cell.setBackground(Color.red);
			    }
			    else if(type.equals("HTTP")) {
			    	cell.setBackground(Color.cyan);
			    }
	
			    else if(type.equals("ipv4")) {
		    	cell.setBackground(Color.blue);
			    }
			    else if(type.equals("ipv6")) {
		    	cell.setBackground(Color.pink);
			    }
			    else {
			    	cell.setBackground(Color.lightGray);
			    }
			  
			    return cell;
		}}
		 table.setDefaultRenderer(Object.class, new TableRenderer());
		 textArea = new JTextArea();
		 textArea.setFont(new Font("Monospaced", Font.PLAIN, 16));
		 textArea.setBounds(0, 49, 1890, 322);

		 JSplitPane sp1 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, jp1, new JScrollPane(table));
		 
		 textField = new JTextField();
		 textField.setBounds(180, 5, 400, 30);
		 jp1.add(textField);
		 textField.setColumns(10);
		 
		 JButton button_1 = new JButton("过滤");
		 button_1.addMouseListener(new MouseAdapter() {
		 	@Override
		 	public void mouseClicked(MouseEvent e) {
		 		if(start)Catch.end=false;
		 		text=textField.getText(); 		
		 		new Thread(new Runnable() {
					public void run() {
							try {
								Catch.fil();
							} catch (ScriptException e) {
								text="";
								textField.setText("");
								JOptionPane.showMessageDialog(null, "输入格式有误，请重新输入", "警告",JOptionPane.WARNING_MESSAGE);  
								try {
									Catch.fil();
								} catch (ScriptException e1) {
									e1.printStackTrace();
								}
								Catch.end=true;
							}	
					}
				}).start();
		 	}
		 });
		 button_1.setBounds(600, 5, 80, 30);
		 jp1.add(button_1);
		 
		 JButton button_2 = new JButton("统计数据集");
		 button_2.setBounds(700, 5, 120, 30);
		 button_2.addMouseListener(new MouseAdapter() {
		 	@Override
		 	public void mouseClicked(MouseEvent e) {
		 		if(start==true) {
			 		new Analysis(Catch.cons).getChartPanel();
			 		Catch.flag=true;
			 		}
			 		else new Analysis();
		 	}
		 });
		 jp1.add(button_2);
		 
		 
		 DefaultMutableTreeNode root=new DefaultMutableTreeNode("");
		 tree = new JTree(root);
		 tree.setFont(new Font("宋体", Font.PLAIN, 18));
		 DefaultTreeCellRenderer render = new DefaultTreeCellRenderer();
		 render.setLeafIcon(null);
		 render.setOpenIcon(new ImageIcon("src/open.png"));
		 render.setClosedIcon(new ImageIcon("src/closed.png"));
		 tree.setCellRenderer(render);
		 JScrollPane jp3=new JScrollPane(tree); 
		 
		 
		 JSplitPane sp2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, jp3,new JScrollPane(textArea));
		 
		
		 JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, sp1, sp2);
		 container.add(splitPane,BorderLayout.CENTER);
		 setLocationRelativeTo(null);
	     setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
	     setVisible(true);
	     sp1.setDividerLocation(0.095);
	     sp2.setDividerLocation(0.3);
	     splitPane.setDividerLocation(0.6);
	     setExtendedState(JFrame.MAXIMIZED_BOTH); 
	}
//保存数据集
public void save(File f) {
		  try {
			  
		      FileOutputStream outputStream;
			  outputStream = new FileOutputStream(f);
			  ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
		      objectOutputStream.writeObject(Catch.pacList);
		      //最后记得关闭资源，objectOutputStream.close()内部已经将outputStream对象资源释放了，所以只需要关闭objectOutputStream即可
		      objectOutputStream.close();
		} catch (IOException e1) {
			e1.printStackTrace();
		}//创建文件字节输出流对象
		
	}
//加载数据集
@SuppressWarnings({ "resource", "unchecked" })
public ArrayList<myPacket> load(File f){
	ArrayList<myPacket> list=new ArrayList<myPacket>();
	try {
	    FileInputStream inputStream;
		inputStream = new FileInputStream(f);
		ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
		list=(ArrayList<myPacket>)objectInputStream.readObject();
	} 
	catch (IOException | ClassNotFoundException e) {
		e.printStackTrace();
	}//创建文件字节输出流对象
	return list;
}	
}
