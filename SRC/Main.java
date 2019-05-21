package 流量分析;

import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import com.jtattoo.plaf.fast.FastLookAndFeel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

public class Main {

	private JFrame frame;
	private runJpcap jp;
    public static JList<String> list;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Main window = new Main();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	/**
	 * Create the application.
	 */
	public Main() {
		initialize();
		jp=new runJpcap();
	}


	private void initialize() {
		
		frame = new JFrame();
		try {

			UIManager.setLookAndFeel(new FastLookAndFeel());
            JFrame.setDefaultLookAndFeelDecorated(true);
            JDialog.setDefaultLookAndFeelDecorated(true);
        } catch (Exception e) {
            System.err.println("Something went wrong!");
        }

		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setTitle("流量分析");
		frame.setBounds(560, 240, 800, 600);
		frame.getContentPane().setLayout(null);
		
		JLabel lblNewLabel = new JLabel("选择网卡：");
		lblNewLabel.setBounds(172, 378, 76, 15);
		frame.getContentPane().add(lblNewLabel);
		
		JLabel device = new JLabel("");
		device.setBounds(245, 378, 334, 15);
		frame.getContentPane().add(device);
		
		list = new JList<String>();
		list.setBounds(172, 155, 400, 200);
		list.addListSelectionListener(new ListSelectionListener() {
			 public void valueChanged(ListSelectionEvent e)
			 {
				 device.setText(""+list.getSelectedValue());              
		     }
	     });
		frame.getContentPane().add(list);
		
		JScrollPane scrollPane = new JScrollPane(list);
		scrollPane.setBounds(172, 155, 410, 200);
		frame.getContentPane().add(scrollPane);
		
	
		JButton btnNewButton = new JButton("刷新");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new Thread(new Runnable() {
					public void run() {
					jp.getDevices();}
				}).start();
			}
		});
		btnNewButton.setBounds(486, 100, 93, 30);
		frame.getContentPane().add(btnNewButton);
		
		JButton btnNewButton_1 = new JButton("开始");
		
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(list.getSelectedIndex()!=-1) {
					btnNewButton_1.setEnabled(true);
					catchPackets ca=new catchPackets(list.getSelectedIndex());
					ca.setVisible(true);
					}
				else JOptionPane.showMessageDialog(null, "请选择网卡", "提示",JOptionPane.INFORMATION_MESSAGE);  
			}
		});
		btnNewButton_1.setBounds(486, 430, 93, 30);
		frame.getContentPane().add(btnNewButton_1);
		
		JButton button = new JButton("历史数据集");
		button.addMouseListener(new MouseAdapter() {
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
		button.setBounds(172, 430, 140, 30);
		frame.getContentPane().add(button);
			
		
	}
}
