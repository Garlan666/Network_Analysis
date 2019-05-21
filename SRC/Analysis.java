package 流量分析;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridLayout;
import java.text.DecimalFormat;  
import java.text.NumberFormat; 
import java.text.SimpleDateFormat;
import java.util.Date;

import org.jfree.chart.ChartFactory;  
import org.jfree.chart.ChartPanel;  
import org.jfree.chart.JFreeChart;  
import org.jfree.chart.axis.CategoryAxis;  
import org.jfree.chart.axis.DateAxis;  
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.labels.ItemLabelAnchor;
import org.jfree.chart.labels.ItemLabelPosition;
import org.jfree.chart.labels.StandardCategoryItemLabelGenerator;
import org.jfree.chart.plot.CategoryPlot;  
import org.jfree.chart.plot.PlotOrientation;
//import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.BarRenderer3D;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
//import org.jfree.data.category.CategoryDataset;  
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;  
import org.jfree.chart.plot.PiePlot; 
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.ui.TextAnchor;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.time.RegularTimePeriod;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimeSeries;  
import org.jfree.data.time.TimeSeriesCollection;  
import javax.swing.JFrame; 

public class Analysis extends JFrame{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static ChartPanel frame1;
	static ChartPanel frame2;
	static ChartPanel frame3;
	static JFrame frame=new JFrame("Java数据统计图");  
	
	@SuppressWarnings("deprecation")
	public  Analysis(int cons[]){  
		if(frame1!=null)frame.remove(frame1);
		if(frame2!=null)frame.remove(frame2);
		if(frame3!=null)frame.remove(frame3);
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();  
        dataset.addValue(cons[0], "TCP", "");   
        dataset.addValue(cons[1], "UDP", ""); 
        dataset.addValue(cons[2], "HTTP", ""); 
        dataset.addValue(cons[3], "ARP", "");   
        dataset.addValue(cons[4], "ICMP", "");  
        dataset.addValue(cons[5], "IPv4", "");
        dataset.addValue(cons[6], "IPv6", "");
        dataset.addValue(cons[7], "其他", "");
        JFreeChart chart = ChartFactory.createBarChart3D(  
                            "数据包协议", // 图表标题  
                            "数据包协议种类", // 目录轴的显示标签  
                            "数量", // 数值轴的显示标签  
                            dataset, // 数据集  
                            PlotOrientation.VERTICAL, // 图表方向：水平、垂直  
                            true,// 是否显示图例(对于简单的柱状图必须是false)  
                            false,// 是否生成工具  
                            false// 是否生成URL链接  
                            );  
        CategoryPlot categoryplot = (CategoryPlot) chart.getPlot();
        BarRenderer3D renderer = new BarRenderer3D();
        renderer.setSeriesPaint(0, Color.green);//设置各柱形颜色
        renderer.setSeriesPaint(1, Color.yellow); 
        renderer.setSeriesPaint(2, Color.cyan);
        renderer.setSeriesPaint(3, Color.orange);
        renderer.setSeriesPaint(4, Color.red);
        renderer.setSeriesPaint(5, Color.blue);
        renderer.setSeriesPaint(6, Color.pink);
        renderer.setSeriesPaint(7, Color.lightGray);
        
        renderer.setMaximumBarWidth(0.05);//设置柱形宽度
        
        renderer.setBaseItemLabelsVisible(true); //设置数值显示
        renderer.setBaseItemLabelPaint(Color.BLACK);//设置数值颜色，默认黑色
        renderer.setBaseItemLabelFont(new Font("SansSerif", Font.PLAIN, 12));
        
        ItemLabelPosition itemLabelPositionFallback=new ItemLabelPosition(   
        		ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER,   
        		TextAnchor.HALF_ASCENT_LEFT,0D);   
        renderer.setPositiveItemLabelPositionFallback(itemLabelPositionFallback);   
        renderer.setNegativeItemLabelPositionFallback(itemLabelPositionFallback);   
        categoryplot.setRenderer(renderer) ;
        
        renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
          
        //从这里开始  
        CategoryPlot plot=chart.getCategoryPlot();//获取图表区域对象  
        CategoryAxis domainAxis=plot.getDomainAxis();//水平底部列表  
        domainAxis.setLabelFont(new Font("黑体",Font.BOLD,14));//水平底部标题  
        domainAxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));//垂直标题  
        ValueAxis rangeAxis=plot.getRangeAxis();//获取柱状  
        rangeAxis.setLabelFont(new Font("黑体",Font.BOLD,15));  
        chart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
        chart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体  
        plot.setRenderer(renderer);
        //到这里结束，虽然代码有点多，但只为一个目的，解决汉字乱码问题  
            
        frame1=new ChartPanel(chart,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame 
        frame.setBounds(560, 0, 800, 770);  
        frame.add(frame1);
 	    frame.setVisible(true);
 	    frame.setLayout(new GridLayout(3,2,10,10));
 	    
 	   DefaultPieDataset dataset2 = new DefaultPieDataset();  
       dataset2.setValue("TCP",cons[0]);  
       dataset2.setValue("UDP",cons[1]);  
       dataset2.setValue("HTTP",cons[2]);  
       dataset2.setValue("ARP",cons[3]);  
       dataset2.setValue("ICMP",cons[4]);
       dataset2.setValue("IPv4",cons[5]);  
       dataset2.setValue("IPv6",cons[6]);
       dataset2.setValue("其他",cons[7]);
       JFreeChart chart2 = ChartFactory.createPieChart3D("数据包协议",dataset2,true,false,false);
     //设置百分比  
       PiePlot pieplot = (PiePlot) chart2.getPlot(); //获取图表区域对象   
       DecimalFormat df = new DecimalFormat("0.00%");//获得一个DecimalFormat对象，主要是设置小数问题  
       NumberFormat nf = NumberFormat.getNumberInstance();//获得一个NumberFormat对象  
       StandardPieSectionLabelGenerator sp1 = new StandardPieSectionLabelGenerator("{0}  {2}", nf, df);//获得StandardPieSectionLabelGenerator对象  
       pieplot.setLabelGenerator(sp1);//设置饼图显示百分比 
       pieplot.setNoDataMessage("无数据显示");  
       pieplot.setCircular(false);  
       pieplot.setLabelGap(0.02D);  
     
       pieplot.setIgnoreNullValues(true);//设置不显示空值  
       pieplot.setIgnoreZeroValues(true);//设置不显示负值    
        
       chart2.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体  
        
       
       pieplot.setSectionOutlinesVisible(false);        
       pieplot.setNoDataMessage("没有可供使用的数据！");        
       pieplot.setSectionPaint("TCP", Color.green);        
       pieplot.setSectionPaint("UDP", Color.yellow);        
       pieplot.setSectionPaint("HTTP", Color.cyan);        
       pieplot.setSectionPaint("ARP", Color.orange); 
       pieplot.setSectionPaint("ICMP", Color.red); 
       pieplot.setSectionPaint("IPv4", Color.blue); 
       pieplot.setSectionPaint("IPv6", Color.pink); 
       pieplot.setSectionPaint("其他", Color.lightGray); 
       //就是这个地方，实现了对各个key对应饼图区域的颜色设置        
        
       pieplot.setLabelFont(new Font("SansSerif", Font.PLAIN, 12));  //解决乱码      
       pieplot.setCircular(false);        
       pieplot.setLabelGap(0.02);  
       
       chart2.getLegend().setItemFont(new Font("黑体",Font.BOLD,10));  
       
       frame2=new ChartPanel(chart2,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
       frame.add(frame2);
	   frame.setVisible(true);
	   
	   TimeSeries timeseries = new TimeSeries("1秒钟内数据包数量", org.jfree.data.time.Second.class);
	   int pacnum=0;
	   Date []dd=new Date[21];
	   RegularTimePeriod []period=new RegularTimePeriod[21];
	   for(int i=0,j=0;i<Catch.pacList.size()-1;i++) {
		   dd[j%21]=new Date(Catch.pacList.get(i).usec);
		   dd[(j+1)%21]=new Date(Catch.pacList.get(i+1).usec);
		   if(dd[j%21].getSeconds()==dd[(j+1)%21].getSeconds()) {
			   pacnum++;
			   if(i+1!=Catch.pacList.size()-1)continue;
			   else if(i==Catch.pacList.size()-2)pacnum++;
		   }
		   period[j%21]=new Second(dd[j%21].getSeconds(),dd[j%21].getMinutes(),dd[j%21].getHours(), dd[j%21].getDay()+2, (dd[j%21].getMonth()+1), dd[j%21].getYear()+1900);
		   timeseries.add(period[j%21], pacnum);
		   if(j>=20)timeseries.delete(period[(j-20)%21]);
		   j++;
		   pacnum=0;
		   } 
	       TimeSeriesCollection timeseriescollection = new TimeSeriesCollection(); 
	       timeseriescollection.addSeries(timeseries); 
	   
       JFreeChart jfreechart = ChartFactory.createTimeSeriesChart("总数据包", "统计间隔为1秒钟", "数量",timeseriescollection, true, true, true);
       XYPlot xyplot =(XYPlot) jfreechart.getPlot();  
       DateAxis dateaxis = (DateAxis) xyplot.getDomainAxis();  
       dateaxis.setDateFormatOverride(new SimpleDateFormat("HH:mm:ss"));   
       dateaxis.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题  
       dateaxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题
       
       xyplot.setBackgroundPaint(Color.WHITE);
       xyplot.setRangeGridlinesVisible(true);
       xyplot.setRangeGridlinePaint(Color.LIGHT_GRAY);// 虚线色彩 
       org.jfree.chart.renderer.xy.XYItemRenderer xyitemrenderer = xyplot.getRenderer();
          if(xyitemrenderer instanceof XYLineAndShapeRenderer)
          {//显示节点
              XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyitemrenderer;
              xylineandshaperenderer.setBaseShapesVisible(true);
              xylineandshaperenderer.setBaseShapesFilled(true);
              
          }
          XYItemRenderer xyitem = xyplot.getRenderer();
          xyitem.setBaseItemLabelsVisible(true);
          xyitem.setBasePositiveItemLabelPosition((new ItemLabelPosition(ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER)));
          XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyplot.getRenderer();
          //设置曲线是否显示数据点
          xylineandshaperenderer.setBaseShapesVisible(true);
          xyplot.setRenderer(xyitemrenderer);
          
       ValueAxis rangeAxis1=xyplot.getRangeAxis();//获取柱状  
       rangeAxis1.setLabelFont(new Font("黑体",Font.BOLD,15));  
       jfreechart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
       jfreechart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
       

       
       frame3=new ChartPanel(jfreechart,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
       frame.add(frame3); 
	   frame.setVisible(true);
	   
	   frame.addWindowListener(new java.awt.event.WindowAdapter() {
	    	public void windowClosing(java.awt.event.WindowEvent e) {
	    		Catch.flag=false;//要处理的事件
	    		try {
					Thread.sleep(50);
				} catch (InterruptedException e1) {
					e1.printStackTrace();
				}
	    		frame.remove(frame1);
	    		frame.remove(frame2);
	    		frame.remove(frame3);
	    		 
	    		}
	    	});
    }
	
	
	
	
	@SuppressWarnings("deprecation")
	public  Analysis() {
		if(frame1!=null)frame.remove(frame1);
		if(frame2!=null)frame.remove(frame2);
		if(frame3!=null)frame.remove(frame3);
		int []count= {0,0,0,0,0,0,0,0};
		for(int i=0;i<Catch.pacList.size();i++) {
			myPacket mp=Catch.pacList.get(i);
			switch(mp.pro) {
			case "TCP":count[0]++;break;
			case "UDP":count[1]++;break;
			case "HTTP":count[2]++;break;
			case "ARP":count[3]++;break;
			case "ICMP":count[4]++;break;
			case "ipv4":count[5]++;break;
			case "ipv6":count[6]++;break;
			default:count[7]++;break;
			}
		}
		
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();  
        dataset.addValue(count[0], "TCP", "");   
        dataset.addValue(count[1], "UDP", ""); 
        dataset.addValue(count[2], "HTTP", ""); 
        dataset.addValue(count[3], "ARP", "");   
        dataset.addValue(count[4], "ICMP", "");  
        dataset.addValue(count[5], "IPv4", "");
        dataset.addValue(count[6], "IPv6", "");
        dataset.addValue(count[7], "其他", "");
        JFreeChart chart = ChartFactory.createBarChart3D(  
                            "数据包协议", // 图表标题  
                            "数据包协议种类", // 目录轴的显示标签  
                            "数量", // 数值轴的显示标签  
                            dataset, // 数据集  
                            PlotOrientation.VERTICAL, // 图表方向：水平、垂直  
                            true,// 是否显示图例(对于简单的柱状图必须是false)  
                            false,// 是否生成工具  
                            false// 是否生成URL链接  
                            );  
        CategoryPlot categoryplot = (CategoryPlot) chart.getPlot();
        BarRenderer3D renderer = new BarRenderer3D();
        renderer.setSeriesPaint(0, Color.green);//设置各柱形颜色
        renderer.setSeriesPaint(1, Color.yellow); 
        renderer.setSeriesPaint(2, Color.cyan);
        renderer.setSeriesPaint(3, Color.orange);
        renderer.setSeriesPaint(4, Color.red);
        renderer.setSeriesPaint(5, Color.blue);
        renderer.setSeriesPaint(6, Color.pink);
        renderer.setSeriesPaint(7, Color.lightGray);
        
        renderer.setMaximumBarWidth(0.05);//设置柱形宽度
        
        renderer.setBaseItemLabelsVisible(true); //设置数值显示
        renderer.setBaseItemLabelPaint(Color.BLACK);//设置数值颜色，默认黑色
        renderer.setBaseItemLabelFont(new Font("SansSerif", Font.PLAIN, 12));
        
        ItemLabelPosition itemLabelPositionFallback=new ItemLabelPosition(   
        		ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER,   
        		TextAnchor.HALF_ASCENT_LEFT,0D);   
        renderer.setPositiveItemLabelPositionFallback(itemLabelPositionFallback);   
        renderer.setNegativeItemLabelPositionFallback(itemLabelPositionFallback);   
        categoryplot.setRenderer(renderer) ;
        
        renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
          
        //从这里开始  
        CategoryPlot plot=chart.getCategoryPlot();//获取图表区域对象  
        CategoryAxis domainAxis=plot.getDomainAxis();//水平底部列表  
        domainAxis.setLabelFont(new Font("黑体",Font.BOLD,14));//水平底部标题  
        domainAxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));//垂直标题  
        ValueAxis rangeAxis=plot.getRangeAxis();//获取柱状  
        rangeAxis.setLabelFont(new Font("黑体",Font.BOLD,15));  
        chart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
        chart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体  
        plot.setRenderer(renderer);
        //到这里结束，虽然代码有点多，但只为一个目的，解决汉字乱码问题  
            
        frame1=new ChartPanel(chart,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame 
        frame.setBounds(560, 0, 800, 770);  
        frame.add(frame1);
 	    frame.setVisible(true);
 	    frame.setLayout(new GridLayout(3,2,10,10));
 	    
 	   DefaultPieDataset dataset2 = new DefaultPieDataset();  
       dataset2.setValue("TCP",count[0]);  
       dataset2.setValue("UDP",count[1]);  
       dataset2.setValue("HTTP",count[2]);  
       dataset2.setValue("ARP",count[3]);  
       dataset2.setValue("ICMP",count[4]);
       dataset2.setValue("IPv4",count[5]);  
       dataset2.setValue("IPv6",count[6]);
       dataset2.setValue("其他",count[7]);
       JFreeChart chart2 = ChartFactory.createPieChart3D("数据包协议",dataset2,true,false,false);
     //设置百分比  
       PiePlot pieplot = (PiePlot) chart2.getPlot(); //获取图表区域对象   
       DecimalFormat df = new DecimalFormat("0.00%");//获得一个DecimalFormat对象，主要是设置小数问题  
       NumberFormat nf = NumberFormat.getNumberInstance();//获得一个NumberFormat对象  
       StandardPieSectionLabelGenerator sp1 = new StandardPieSectionLabelGenerator("{0}  {2}", nf, df);//获得StandardPieSectionLabelGenerator对象  
       pieplot.setLabelGenerator(sp1);//设置饼图显示百分比 
       pieplot.setNoDataMessage("无数据显示");  
       pieplot.setCircular(false);  
       pieplot.setLabelGap(0.02D);  
     
       pieplot.setIgnoreNullValues(true);//设置不显示空值  
       pieplot.setIgnoreZeroValues(true);//设置不显示负值    
        
       chart2.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体  
        
       
       pieplot.setSectionOutlinesVisible(false);        
       pieplot.setNoDataMessage("没有可供使用的数据！");        
       pieplot.setSectionPaint("TCP", Color.green);        
       pieplot.setSectionPaint("UDP", Color.yellow);        
       pieplot.setSectionPaint("HTTP", Color.cyan);        
       pieplot.setSectionPaint("ARP", Color.orange); 
       pieplot.setSectionPaint("ICMP", Color.red); 
       pieplot.setSectionPaint("IPv4", Color.blue); 
       pieplot.setSectionPaint("IPv6", Color.pink); 
       pieplot.setSectionPaint("其他", Color.lightGray); 
       //就是这个地方，实现了对各个key对应饼图区域的颜色设置        
        
       pieplot.setLabelFont(new Font("SansSerif", Font.PLAIN, 12));  //解决乱码      
       pieplot.setCircular(false);        
       pieplot.setLabelGap(0.02);  
       
       chart2.getLegend().setItemFont(new Font("黑体",Font.BOLD,10));  
       
       frame2=new ChartPanel(chart2,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
       frame.add(frame2);
	   frame.setVisible(true);
	   
	   TimeSeries timeseries = new TimeSeries("1秒钟内数据包数量", org.jfree.data.time.Second.class);
	   int pacnum=0;
	   for(int i=0;i<Catch.pacList.size()-1;i++) {
		   Date d=new Date(Catch.pacList.get(i).usec);
		   Date dnext=new Date(Catch.pacList.get(i+1).usec);
		   if(d.getSeconds()==dnext.getSeconds()) {
			   pacnum++;
			   if(i+1!=Catch.pacList.size()-1)continue;
			   else if(i==Catch.pacList.size()-2)pacnum++;
		   }
		   timeseries.add(new Second(d.getSeconds(),d.getMinutes(),d.getHours(), d.getDay()+2, (d.getMonth()+1), d.getYear()+1900), pacnum);
		   pacnum=0;
	   }
	   
	   
	   TimeSeriesCollection timeseriescollection = new TimeSeriesCollection(); 
       timeseriescollection.addSeries(timeseries); 
       
       JFreeChart jfreechart = ChartFactory.createTimeSeriesChart("总数据包", "统计间隔为1秒钟", "数量",timeseriescollection, true, true, true);
       XYPlot xyplot = (XYPlot) jfreechart.getPlot();  
       DateAxis dateaxis = (DateAxis) xyplot.getDomainAxis();  
       dateaxis.setDateFormatOverride(new SimpleDateFormat("HH:mm:ss"));   
       dateaxis.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题  
       dateaxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题
       
       xyplot.setBackgroundPaint(Color.WHITE);
       xyplot.setRangeGridlinesVisible(true);
       xyplot.setRangeGridlinePaint(Color.LIGHT_GRAY);// 虚线色彩 
       org.jfree.chart.renderer.xy.XYItemRenderer xyitemrenderer = xyplot.getRenderer();
          if(xyitemrenderer instanceof XYLineAndShapeRenderer)
          {//显示节点
              XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyitemrenderer;
              xylineandshaperenderer.setBaseShapesVisible(true);
              xylineandshaperenderer.setBaseShapesFilled(true);
              
          }
          XYItemRenderer xyitem = xyplot.getRenderer();
          xyitem.setBaseItemLabelsVisible(true);
          xyitem.setBasePositiveItemLabelPosition((new ItemLabelPosition(ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER)));
          XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyplot.getRenderer();
          //设置曲线是否显示数据点
          xylineandshaperenderer.setBaseShapesVisible(true);
          xyplot.setRenderer(xyitemrenderer);
          
       ValueAxis rangeAxis1=xyplot.getRangeAxis();//获取柱状  
       rangeAxis1.setLabelFont(new Font("黑体",Font.BOLD,15));  
       jfreechart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
       jfreechart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
       

       
       frame3=new ChartPanel(jfreechart,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
       frame.add(frame3); 
	   frame.setVisible(true);
	   
	   frame.addWindowListener(new java.awt.event.WindowAdapter() {
	    	public void windowClosing(java.awt.event.WindowEvent e) {
	    		
	    		frame.remove(frame1);
	    		frame.remove(frame2);
	    		frame.remove(frame3);
	    		}
	    	});
	}
	
	
	
	
	
	@SuppressWarnings("deprecation")
	public static void redraw(int cons[]) {
		frame.remove(frame1);
		frame.remove(frame2);
		frame.remove(frame3);
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();  
        dataset.addValue(cons[0], "TCP", "");   
        dataset.addValue(cons[1], "UDP", ""); 
        dataset.addValue(cons[2], "HTTP", ""); 
        dataset.addValue(cons[3], "ARP", "");   
        dataset.addValue(cons[4], "ICMP", "");  
        dataset.addValue(cons[5], "IPv4", "");
        dataset.addValue(cons[6], "IPv6", "");
        dataset.addValue(cons[7], "其他", "");
        JFreeChart chart = ChartFactory.createBarChart3D(  
                "数据包协议", // 图表标题  
                "数据包协议种类", // 目录轴的显示标签  
                "数量", // 数值轴的显示标签  
                dataset, // 数据集  
                PlotOrientation.VERTICAL, // 图表方向：水平、垂直  
                true,// 是否显示图例(对于简单的柱状图必须是false)  
                false,// 是否生成工具  
                false// 是否生成URL链接  
                ); 
        CategoryPlot categoryplot = (CategoryPlot) chart.getPlot();
        BarRenderer3D renderer = new BarRenderer3D();
        renderer.setSeriesPaint(0, Color.green);//设置各柱形颜色
        renderer.setSeriesPaint(1, Color.yellow); 
        renderer.setSeriesPaint(2, Color.cyan);
        renderer.setSeriesPaint(3, Color.orange);
        renderer.setSeriesPaint(4, Color.red);
        renderer.setSeriesPaint(5, Color.blue);
        renderer.setSeriesPaint(6, Color.pink);
        renderer.setSeriesPaint(7, Color.lightGray);
        
        renderer.setMaximumBarWidth(0.05);//设置柱形宽度
        
        renderer.setBaseItemLabelsVisible(true); //设置数值显示
        renderer.setBaseItemLabelPaint(Color.BLACK);//设置数值颜色，默认黑色 
        renderer.setBaseItemLabelFont(new Font("SansSerif", Font.PLAIN, 12));
        
        
        ItemLabelPosition itemLabelPositionFallback=new ItemLabelPosition(   
        		ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER,   
        		TextAnchor.HALF_ASCENT_LEFT,0D);   
        renderer.setPositiveItemLabelPositionFallback(itemLabelPositionFallback);   
        renderer.setNegativeItemLabelPositionFallback(itemLabelPositionFallback);   
        categoryplot.setRenderer(renderer) ;
        
        renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
  
        CategoryPlot plot=chart.getCategoryPlot();//获取图表区域对象  
        CategoryAxis domainAxis=plot.getDomainAxis();//水平底部列表  
        domainAxis.setLabelFont(new Font("黑体",Font.BOLD,14));//水平底部标题  
        domainAxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));//垂直标题  
        ValueAxis rangeAxis=plot.getRangeAxis();//获取柱状  
        rangeAxis.setLabelFont(new Font("黑体",Font.BOLD,15));  
        chart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
        chart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
        plot.setRenderer(renderer);
        frame1=new ChartPanel(chart,true);
        frame.add(frame1); 
 	    frame.setVisible(true);
 	    
 	    
 	   DefaultPieDataset dataset2 = new DefaultPieDataset();  
       dataset2.setValue("TCP",cons[0]);  
       dataset2.setValue("UDP",cons[1]);  
       dataset2.setValue("HTTP",cons[2]);  
       dataset2.setValue("ARP",cons[3]);  
       dataset2.setValue("ICMP",cons[4]);
       dataset2.setValue("IPv4",cons[5]); 
       dataset2.setValue("IPv6",cons[6]); 
       dataset2.setValue("其他",cons[7]);
       JFreeChart chart2 = ChartFactory.createPieChart3D("数据包协议",dataset2,true,false,false);
     //设置百分比  
       PiePlot pieplot = (PiePlot) chart2.getPlot();  //获取图表区域对象  
       DecimalFormat df = new DecimalFormat("0.00%");//获得一个DecimalFormat对象，主要是设置小数问题  
       NumberFormat nf = NumberFormat.getNumberInstance();//获得一个NumberFormat对象  
       StandardPieSectionLabelGenerator sp1 = new StandardPieSectionLabelGenerator("{0}  {2}", nf, df);//获得StandardPieSectionLabelGenerator对象  
       pieplot.setLabelGenerator(sp1);//设置饼图显示百分比 
       pieplot.setNoDataMessage("无数据显示");  
       pieplot.setCircular(false);  
       pieplot.setLabelGap(0.02D);  
     
       pieplot.setIgnoreNullValues(true);//设置不显示空值  
       pieplot.setIgnoreZeroValues(true);//设置不显示负值    
       chart2.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体  
      
       pieplot.setSectionOutlinesVisible(false);        
       pieplot.setNoDataMessage("没有可供使用的数据！");        
       pieplot.setSectionPaint("TCP", Color.green);        
       pieplot.setSectionPaint("UDP", Color.yellow);        
       pieplot.setSectionPaint("HTTP", Color.cyan);        
       pieplot.setSectionPaint("ARP", Color.orange); 
       pieplot.setSectionPaint("ICMP", Color.red); 
       pieplot.setSectionPaint("IPv4", Color.blue);
       pieplot.setSectionPaint("IPv6", Color.pink);
       pieplot.setSectionPaint("其他", Color.lightGray); 
       //就是这个地方，实现了对各个key对应饼图区域的颜色设置        
        
       pieplot.setLabelFont(new Font("SansSerif", Font.PLAIN, 12));  //解决乱码        
       pieplot.setCircular(false);        
       pieplot.setLabelGap(0.02);  
       chart2.getLegend().setItemFont(new Font("黑体",Font.BOLD,10)); 
       
       frame2=new ChartPanel(chart2,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
       frame.add(frame2);  
	   frame.setVisible(true);

	   TimeSeries timeseries = new TimeSeries("1秒钟内数据包数量", org.jfree.data.time.Second.class);
	   int pacnum=0;
	   Date []dd=new Date[21];
	   RegularTimePeriod []period=new RegularTimePeriod[21];
	   for(int i=0,j=0;i<Catch.pacList.size()-1;i++) {
		   dd[j%21]=new Date(Catch.pacList.get(i).usec);
		   dd[(j+1)%21]=new Date(Catch.pacList.get(i+1).usec);
		   if(dd[j%21].getSeconds()==dd[(j+1)%21].getSeconds()) {
			   pacnum++;
			   if(i+1!=Catch.pacList.size()-1)continue;
			   else if(i==Catch.pacList.size()-2)pacnum++;
		   }
		   period[j%21]=new Second(dd[j%21].getSeconds(),dd[j%21].getMinutes(),dd[j%21].getHours(), dd[j%21].getDay()+2, (dd[j%21].getMonth()+1), dd[j%21].getYear()+1900);
		   timeseries.add(period[j%21], pacnum);
		   if(j>=20)timeseries.delete(period[(j-20)%21]);
		   j++;
		   pacnum=0;
		   } 
	       
	       TimeSeriesCollection timeseriescollection = new TimeSeriesCollection(); 
	       timeseriescollection.addSeries(timeseries);
		   
	       JFreeChart jfreechart = ChartFactory.createTimeSeriesChart("总数据包", "统计间隔为1秒钟", "数量",timeseriescollection, true, true, true);
	       XYPlot xyplot = (XYPlot) jfreechart.getPlot();
	       
	       xyplot.setBackgroundPaint(Color.WHITE);
	       xyplot.setRangeGridlinesVisible(true);
	       xyplot.setRangeGridlinePaint(Color.LIGHT_GRAY);// 虚线色彩 
	       org.jfree.chart.renderer.xy.XYItemRenderer xyitemrenderer = xyplot.getRenderer();
	          if(xyitemrenderer instanceof XYLineAndShapeRenderer)
	          {//显示节点
	              XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyitemrenderer;
	              xylineandshaperenderer.setBaseShapesVisible(true);
	              xylineandshaperenderer.setBaseShapesFilled(true);
	              
	          }
	          XYItemRenderer xyitem = xyplot.getRenderer();
	          xyitem.setBaseItemLabelsVisible(true);
	          xyitem.setBasePositiveItemLabelPosition((new ItemLabelPosition(ItemLabelAnchor.OUTSIDE12,TextAnchor.BASELINE_CENTER)));
	          XYLineAndShapeRenderer xylineandshaperenderer = (XYLineAndShapeRenderer)xyplot.getRenderer();
	          //设置曲线是否显示数据点
	          xylineandshaperenderer.setBaseShapesVisible(true);
	          xyplot.setRenderer(xyitemrenderer);

	       DateAxis dateaxis = (DateAxis) xyplot.getDomainAxis();  
	       dateaxis.setDateFormatOverride(new SimpleDateFormat("HH:mm:ss"));    
	       dateaxis.setLabelFont(new Font("黑体",Font.BOLD,14));         //水平底部标题  
	       dateaxis.setTickLabelFont(new Font("宋体",Font.BOLD,12));  //垂直标题  
	       ValueAxis rangeAxis1=xyplot.getRangeAxis();//获取柱状  
	       rangeAxis1.setLabelFont(new Font("黑体",Font.BOLD,15));  
	       jfreechart.getLegend().setItemFont(new Font("黑体", Font.BOLD, 15));  
	       jfreechart.getTitle().setFont(new Font("宋体",Font.BOLD,20));//设置标题字体
	       
	       frame3=new ChartPanel(jfreechart,true);//这里也可以用chartFrame,可以直接生成一个独立的Frame  
	       frame.add(frame3); 
		   frame.setVisible(true);
	   
	   frame.addWindowListener(new java.awt.event.WindowAdapter() {
	    	public void windowClosing(java.awt.event.WindowEvent e) {
	    		Catch.flag=false;//要处理的事件 
	    		frame.remove(frame1);
	    		frame.remove(frame2);
	    		frame.remove(frame3);
	    		
	    		}
	    	});
 	    }
	
	public ChartPanel getChartPanel(){  
		return frame1;  
		}
	public ChartPanel getChartPanel2(){  
		return frame2;  
		}
	public ChartPanel getChartPanel3(){  
		return frame3;  
		}
}
