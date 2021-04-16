import java.io.*;
import java.net.*;
import java.util.*;

public class Main
{
	static ServerSocket ss;
	static int op=3389;
	static int lp=3390;

	public static void main(String[] args) throws Exception
	{
		/*设置端口，默认3389转3390
		 取前两个参数作为端口号，不足时使用默认，转换失败时报错退出*/
		if(args.length>=2)
		{
			op=Integer.parseInt(args[0]);
			lp=Integer.parseInt(args[1]);
		}
		System.out.println("Open port:  "+op);
		System.out.println("Local port: "+lp);
		System.out.println();

		//读白名单
		System.out.println("Loading list");
		HashMap<Long, Long> wl = new HashMap<>();
		HashMap<Long, Long> bl = new HashMap<>();
		BufferedReader br = new BufferedReader(new FileReader("ip.txt"));
		String line;
		while((line = br.readLine()) != null)
		{
			String[] sp = line.split("\\|");
			wl.put(Long.parseLong(sp[0]), Long.parseLong(sp[1]));
		}
		br.close();
		//每次连接时都读一次黑名单，开始时不读

		//开端口
		ss = new ServerSocket(op);
		System.out.println("Ready");

		//无限循环监听
		while(true)
		{
			int flag = 0; //0:Accept  1:Deny
			try
			{
				Socket s = ss.accept();
				//获取IP地址
				String ipa = s.getInetAddress().getHostAddress();
				long ip; //10进制IP
				//获取到IPv6时视为本机连接，服务器未开通IPv6
				try
				{
					ip = toDecIP(ipa);
				}catch(Exception e)
				{
					ip=toDecIP("127.0.0.1");
				}
				//读黑名单，读前清空
				bl.clear();
				br = new BufferedReader(new FileReader("bl.txt"));
				while((line = br.readLine()) != null && !line.isEmpty())
				{
					/*当前版本为补全后面两位，以后改成自动补齐剩下的位*/
					bl.put(toDecIP(line + ".0.0"), toDecIP(line + ".255.255"));
				}
				br.close();
				//开始筛选
				//黑名单最优先
				for(Map.Entry<Long, Long> t : bl.entrySet())
				{
					if(ip >= t.getKey() && ip <= t.getValue())
					{
						System.out.println(ipa + "\t" + op + "\tDenied\tblacklist");
						flag = 1;
						break;
					}
				}
				if(flag != 0)
				{
					s.close();
					continue;
				}
				flag = 1;
				//白名单/国内IP
				for(Map.Entry<Long, Long> t : wl.entrySet())
				{
					if(ip >= t.getKey() && ip <= t.getValue())
					{
						System.out.println(ipa + "\t" + op + "\tAccepted\tCN");
						flag = 0;
						break;
					}
				}
				//国外IP
				if(flag != 0)
				{
					System.out.println(ipa + "\t" + op + "\tDenied\tabroad");
					s.close();
					continue;

				}

				//到此意味着这个连接通过所有条件，有正式的新连接进入
				//被AC的连接的IP被记录到文件中
				File ac=new File("ac.txt");
				boolean acf;//文件状态
				//不存在则创建，结果存在acf
				if(!ac.exists())
					acf=ac.createNewFile();
				else
					acf=true; //存在则直接为true
				if(acf)
				{
					//不重复写入
					String[] ips=ipa.split("\\.");
					String pref=ips[0]+"."+ips[1];
					flag=1; //0:exist  1:not exist
					br=new BufferedReader(new FileReader(ac));
					while((line=br.readLine())!=null)
					{
						if(line.equals(pref))
						{
							flag=0;
							break;
						}
					}
					br.close();
					if(flag!=0)
					{
						//写入
						DataOutputStream os=new DataOutputStream(new FileOutputStream(ac,true));
						os.writeBytes(pref+"\n");
						os.flush();
						os.close();
					}
				}

				//连接到本机指定的端口
				Socket c = new Socket("localhost", lp);
				//异步处理两端接收到的数据
				handle(c, s);
				handle(s, c);
			}catch(IOException ignored)
			{
			}
		}
	}

	/**
	 * 把IPv4地址转成10进制格式
	 * @param ip 传入IPv4地址，不接收IPv6
	 * @return IP地址对应的十进制数
	 */
	static long toDecIP(String ip)
	{
		String[] part = ip.split("\\.", 4);
		String _1 = Integer.toHexString(Integer.parseInt(part[0]));
		String _2 = Integer.toHexString(Integer.parseInt(part[1]));
		String _3 = Integer.toHexString(Integer.parseInt(part[2]));
		String _4 = Integer.toHexString(Integer.parseInt(part[3]));
		if(_1.length() < 2)
			_1 = "0" + _1;
		if(_2.length() < 2)
			_2 = "0" + _2;

		if(_3.length() < 2)
			_3 = "0" + _3;

		if(_4.length() < 2)
			_4 = "0" + _4;
		String hex = _1 + _2 + _3 + _4;
		return Long.parseLong(hex, 16);
	}

	/**
	 * 处理两端接收到的信息，把远程端发来的数据转发到本地端，
	 * 把本地端发来的数据转发给远程端
	 * @throws Exception 理论上不会出问题
	 */
	private static void handle(Socket s, Socket c) throws Exception
	{
		DataInputStream is = new DataInputStream(c.getInputStream());
		//1毫秒读一次数据 死循环占资源
		Timer t = new Timer();
		t.schedule(new TimerTask()
		{
			byte[] b; //缓冲区
			int sp=0; //空闲时间

			@Override
			public void run()
			{
				try
				{
					b = new byte[is.available()];
					//读数据，有数据时刷新空闲时间，然后把数据写到另一个socket里面
					if(b.length != 0)
					{
						is.read(b);
						sp = 0;
						DataOutputStream os = new DataOutputStream(s.getOutputStream());
						os.write(b);
						os.flush();
					}else
					{
						//无数据时空闲时间+1
						sp++;
						//超过5分钟自动断开，timer停止
						if(sp > 300000)
						{
							s.close();
							c.close();
							t.cancel();
						}
					}
				}catch(IOException e)
				{
					//如果上面出了状况，则直接中断
					try
					{
						s.close();
						c.close();
					}catch(IOException ignored)
					{
					}
					t.cancel();
				}
			}
		}, 0, 1);
	}
}
