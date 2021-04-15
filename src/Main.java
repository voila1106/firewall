import java.io.*;
import java.net.*;
import java.util.*;

public class Main
{
	static int sp = 0;
	static ServerSocket ss;
	static int op=3389;
	static int lp=3390;

	public static void main(String[] args) throws Exception
	{
		if(args.length>=2)
		{
			op=Integer.parseInt(args[0]);
			lp=Integer.parseInt(args[1]);
		}
		System.out.println("Open port:  "+op);
		System.out.println("Local port: "+lp);
		System.out.println();


		System.out.println("Loading list");

		HashMap<Long, Long> wl = new HashMap<>();
		HashMap<Long, Long> bl = new HashMap<>();
		BufferedReader br = new BufferedReader(new FileReader("ip.txt"));
		String line;
		//StringBuilder sb=new StringBuilder();
		while((line = br.readLine()) != null)
		{
			String[] sp = line.split("\\|");
			wl.put(Long.parseLong(sp[0]), Long.parseLong(sp[1]));
		}
		br.close();
		br = new BufferedReader(new FileReader("bl.txt"));
		while((line = br.readLine()) != null && !line.isEmpty())
		{
			bl.put(toDecIP(line + ".0.0"), toDecIP(line + ".255.255"));
		}
		br.close();
		System.out.println("Ready");


		ss = new ServerSocket(op);
		while(true)
		{
			int flag = 0; //0:Accept  1:Deny
			try
			{
				Socket s = ss.accept();
				String ipa = s.getInetAddress().getHostAddress();
				long ip;
				try
				{
					ip = toDecIP(ipa);
				}catch(Exception e)
				{
					ip=toDecIP("127.0.0.1");
				}

				bl.clear();
				br = new BufferedReader(new FileReader("bl.txt"));
				while((line = br.readLine()) != null && !line.isEmpty())
				{
					bl.put(toDecIP(line + ".0.0"), toDecIP(line + ".255.255"));
				}
				br.close();

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
				for(Map.Entry<Long, Long> t : wl.entrySet())
				{
					if(ip >= t.getKey() && ip <= t.getValue())
					{
						System.out.println(ipa + "\t" + op + "\tAccepted\tCN");
						flag = 0;
						break;
					}
				}
				if(flag != 0)
				{
					System.out.println(ipa + "\t" + op + "\tDenied\tabroad");
					s.close();
					continue;

				}
				sp=0;
				File ac=new File("ac.txt");
				boolean acf=false;
				if(!ac.exists())
					acf=ac.createNewFile();
				else
					acf=true;
				if(acf)
				{
					DataOutputStream os=new DataOutputStream(new FileOutputStream(ac));
					os.writeBytes(ipa+"\n");
					os.flush();
					os.close();
				}


				Socket c = new Socket("localhost", lp);
				handle(c, s);
				handle(s, c);
			}catch(IOException ignored)
			{
			}
		}
	}

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

	private static void handle(Socket s, Socket c) throws Exception
	{
		DataInputStream is = new DataInputStream(c.getInputStream());
		Timer t = new Timer();
		t.schedule(new TimerTask()
		{
			byte[] b;

			@Override
			public void run()
			{
				//System.out.println(sp);
				try
				{
					//s.sendUrgentData(0xff);
					b = new byte[is.available()];
					if(b.length != 0)
					{
						is.read(b);
						sp = 0;
						//System.out.println(new String(b));

						DataOutputStream os = new DataOutputStream(s.getOutputStream());
						os.write(b);
						os.flush();
					}else
					{
						sp++;
						if(sp > 60000)
						{
							s.close();
							c.close();
							ss.close();
//							System.out.println("close");
							ss = new ServerSocket(op);
							t.cancel();
						}
					}
				}catch(IOException e)
				{
					t.cancel();
				}
			}
		}, 0, 1);
	}
}
