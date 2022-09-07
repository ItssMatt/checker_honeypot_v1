using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;

namespace checkerCS
{

	/*				COLORS
	 *				
	 *				1 - White
	 *				2 - Blue
	 *				3 - Red
	 *				4 - Green
	 *				5 - Yellow
	 * */
	class Program
	{
		static string contract;
		static bool _onlyValidCharacters(string line)
		{
			for (int i = 0; i < line.Length; i++)
			{
				if (!((line[i] >= 97 && line[i] <= 122) || (line[i] >= 65 && line[i] <= 90) || (line[i] >= 48 && line[i] <= 57))) return false;
			}
			return true;
		}

		static bool _isValidContract(string line)
		{
			return ((line.Length == 42 && _onlyValidCharacters(line) && line.StartsWith("0x")) ? true : false);
		}

		static void _func()
		{
			if (contract.Equals("0x0")) return;
			if (!_isValidContract(contract))
			{
				print("@3The contract you provided is invalid!\n");
				return;
			}
			try
			{	
				var json = new WebClient().DownloadString(
					"https://api.bscscan.com/api?module=contract&action=getsourcecode&address=" + contract + "&apikey=NQ89E3SU8ZHZFESTE3CJ3S8E4PZ1R4MXQG");
				dynamic deserializedProduct = JsonConvert.DeserializeObject<dynamic>(json);
				if (deserializedProduct["result"][0]["SourceCode"].ToString().Length < 10)
				{
					print("@3The provided contract is not verified! You should NOT buy this token.\n");
					return;
				}
				print("\n@2==========================================================\n\n");
				string path = Directory.GetCurrentDirectory() + @"\temp.txt";
				File.WriteAllText(path, deserializedProduct["result"][0]["SourceCode"].ToString());
				string[] lines = System.IO.File.ReadAllLines(path);
				bool comment = false, lockedliq = false, ownership = false, source_check_def_hny = false, source_check_router = false, in_fnc_transferfrom = false,
					burnedliq = false;
				ulong true_lines = 0, count_lines = 0;
				ushort count_files = 0, honeypot_score = 0, fnc_transferfrom_tampered = 0;
				string pragma = string.Empty;
				foreach (string line in lines)
				{
					count_lines++;
					if (line.Contains("\"language\": \"Solidity\""))
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("This contract is compiled as Multi-Part Files. (UNREADABLE WITH THE CHECKER, CHECK BSCSCAN)");
						Console.ForegroundColor = ConsoleColor.White;
						return;
					}
					if (line.Contains("/*")) comment = true;
					if (line.Contains("*/")) { comment = false; continue; }
					if (!comment && !line.StartsWith("//")) true_lines++;
					if ((line.Contains("function transferFrom(") || 
						(line.Contains("function") && (line.Contains("transferfrom") || line.Contains("TransferFrom") || line.Contains("transferFrom")))) 
						&& !line.Contains(";") && !comment && !line.StartsWith("//")) in_fnc_transferfrom = true;
					else if(in_fnc_transferfrom && (line.Contains("return true;") || line.Contains("}")))
					{
						in_fnc_transferfrom = false;
					}
					if(in_fnc_transferfrom)
					{
						if ((line.Contains("if(from != address(0) && ") && line.Contains("== address(0))")))
						{
							if(fnc_transferfrom_tampered == 0)
							{
								fnc_transferfrom_tampered = 1;
								Console.ForegroundColor = ConsoleColor.Red;
								Console.WriteLine("(!) Function 'transferFrom' has been tampered! (line " + count_lines + "): '" + line + "'");
								Console.ForegroundColor = ConsoleColor.White;
							}
						}
						else if(line.Contains(".call(abi.encodeWithSelector(") && line.Contains("to, value)"))
						{
							fnc_transferfrom_tampered = 2;
							Console.ForegroundColor = ConsoleColor.Red;
							Console.WriteLine("(!) Function 'transferFrom' has been tampered! (line " + count_lines + "): '" + line + "'");
							Console.ForegroundColor = ConsoleColor.White;
						}
					}
					if (line.StartsWith("pragma solidity") && !line.StartsWith("//") && !comment)
					{
						count_files++;
						if (!(line.Contains("0.6") || line.Contains("0.7") || line.Contains("0.8")))
						{
							Console.ForegroundColor = ConsoleColor.Red;
							Console.WriteLine("'" + line + "' (!) LOW COMPILER VERSION");
							Console.ForegroundColor = ConsoleColor.White;
							if(count_files == 1) honeypot_score += 25;
						}
						else
						{
							if (line.Contains("0.6") && count_files == 1) honeypot_score += 5;
							Console.ForegroundColor = (!line.Contains("0.6") ? ConsoleColor.Green : ConsoleColor.Yellow);
							Console.WriteLine("'" + line + "' " + (line.Contains("0.6") ? "(?) MID COMPILER VERSION" : ""));
							Console.ForegroundColor = ConsoleColor.White;
						}
						if (pragma.Equals(string.Empty)) pragma = line;
					}
					else if (line.Contains("address public new"))
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("(!) Found '" + line + "' in the source code!");
						Console.ForegroundColor = ConsoleColor.White;
						honeypot_score += 20;
						source_check_def_hny = true;
					}
					else if ((line.Contains("Owner") || line.Contains("owner")) && (line.Contains("= 0x") || line.Contains("= address(0x")))
					{
						Console.ForegroundColor = ConsoleColor.Red;
						Console.WriteLine("(!) Owner may be set from the source code (line " + count_lines +  "): '" + line + "'");
						Console.ForegroundColor = ConsoleColor.White;
						ownership = true;
					}
					else if (line.Contains("function lock("))
					{
						Console.ForegroundColor = ConsoleColor.Green;
						Console.WriteLine("Liquidity locking function found! '" + line + "'");
						Console.ForegroundColor = ConsoleColor.White;
						lockedliq = true;
					}
					else if(line.Contains("function ") && line.Contains("burn("))
					{
						Console.ForegroundColor = ConsoleColor.Green;
						Console.WriteLine("Liquidity burning function found! '" + line + "'");
						Console.ForegroundColor = ConsoleColor.White;
						burnedliq = true;
					}
					else if (line.Contains("0x") && !line.Contains("0x0"))
					{
						Console.ForegroundColor = ConsoleColor.Yellow;
						Console.WriteLine("Found an address (line " + count_lines + "): '" + line + "'");
						Console.ForegroundColor = ConsoleColor.White;
					} 
					else if (line.Contains("name ") && line.Contains("= \""))
					{
						Console.Write("Token's name: ");
						Console.ForegroundColor = ConsoleColor.Blue;
						string[] splitted = line.Split('\"');
						Console.Write(splitted[1] + "\n");
						Console.ForegroundColor = ConsoleColor.White;
					}
					else if (line.Contains("name ") && line.Contains("= \""))
					{
						Console.Write("Token's name: ");
						Console.ForegroundColor = ConsoleColor.Blue;
						string[] splitted = line.Split('\"');
						Console.Write(splitted[1] + "\n");
						Console.ForegroundColor = ConsoleColor.White;
					}
					else if (line.Contains("symbol ") && line.Contains("= \""))
					{
						Console.Write("Symbol: ");
						Console.ForegroundColor = ConsoleColor.Blue;
						string[] splitted = line.Split('\"');
						Console.Write("$" + splitted[1] + "\n");
						Console.ForegroundColor = ConsoleColor.White;
					}
					else if(line.Contains("router") || line.Contains("Router"))
					{
						source_check_router = true;
					}
				}
				Console.Write("\nThis contract is made out of ");
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.Write(count_files);
				Console.ForegroundColor = ConsoleColor.White;
				Console.Write(" file(s).");
				Console.ForegroundColor = ConsoleColor.Red;
				Console.Write((count_files == 0 ? " (compiled as Multi-Part Files (?))" : "") + "\n");
				Console.ForegroundColor = ConsoleColor.White;
				if (!ownership) Console.WriteLine("You should also check if the ownership is renounced. (Contract -> Read Contract -> 'owner' must be 0x0000)\n");
				Console.Write("Contract lines: ");
				if (true_lines < 250) { Console.ForegroundColor = ConsoleColor.Red; if(!pragma.Contains("0.7") && !pragma.Contains("0.8")) honeypot_score += 25; }
				else if (true_lines >= 250 && true_lines < 350) Console.ForegroundColor = ConsoleColor.Yellow;
				else Console.ForegroundColor = ConsoleColor.Green;
				Console.Write(true_lines + "\n");
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine("Commented lines: " + (count_lines - true_lines).ToString());
				Console.WriteLine("Total lines: " + count_lines + "\n");
				if (true_lines < (count_lines - true_lines) && !pragma.Contains("0.7") && !pragma.Contains("0.8")) honeypot_score += 25;
				if ((true_lines < (count_lines - true_lines) && pragma.Contains("0.6") && count_files == 1 && !lockedliq && burnedliq) || fnc_transferfrom_tampered == 2)
				{
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine("(!) This source code might be using the 'cannot estimate gas' exploit!");
					Console.ForegroundColor = ConsoleColor.White;
					honeypot_score = 100;
				}
				if((true_lines < 180 && pragma.Contains("0.5") && count_files == 1 && source_check_def_hny) || fnc_transferfrom_tampered == 1)
				{
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine("(!) This source code is using the 'INSUFFICIENT_OUTPUT_AMOUNT' exploit!");
					Console.ForegroundColor = ConsoleColor.White;
					honeypot_score = 100;
				}
				if ((true_lines - (count_lines - true_lines) > 500 && source_check_router && count_files == 1 && pragma.Contains("0.6.12") && lockedliq) || 
					honeypot_score == 0)
				{
					Console.ForegroundColor = ConsoleColor.Green;
					Console.WriteLine("(!) This source code looks legit!");
					Console.ForegroundColor = ConsoleColor.White;
					honeypot_score = (pragma.Contains("0.6.12") ? (ushort)1 : (ushort)0);
				}
				if (count_files > 0)
				{
					Console.Write("Honeypot chance: ");
					if (honeypot_score <= 5) Console.ForegroundColor = ConsoleColor.Green;
					else if (honeypot_score > 5 && honeypot_score < 40) Console.ForegroundColor = ConsoleColor.Yellow;
					else Console.ForegroundColor = ConsoleColor.Red;
					Console.Write(honeypot_score + "%" + "\n");
				}
				if(honeypot_score < 40)
				{
					Console.ForegroundColor = ConsoleColor.Yellow;
					Console.WriteLine("(!) Warning! Even though the honeypot score is pretty low, it can also be a rug pull!");
					Console.WriteLine("(!) Pay attention to the token's liquidity and owner, as it is up to him if he will rug the coin!");
				}
				Console.ForegroundColor = ConsoleColor.DarkYellow;
				Console.WriteLine("\nSource code copied at: " + path + "\n");
				Console.ForegroundColor = ConsoleColor.White;
				print("@2==========================================================\n");
			}
			catch (Exception e)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("INVALID CONTRACT! (Make sure the contract does not contain any spaces)");
				Console.ForegroundColor = ConsoleColor.White;
			}
		}

		static void print(string message)
		{
			bool amp = false;
			for (int i = 0; i < message.Length; i++)
			{
				bool hold = false;
				if (!amp)
				{
					if (message[i].Equals('@'))
					{
						amp = true;
						hold = true;
					}
				}
				else
				{
					switch (message[i] - 48)
					{
						case 1:
							{
								Console.ForegroundColor = ConsoleColor.White;
								break;
							}
						case 2:
							{
								Console.ForegroundColor = ConsoleColor.Blue;
								break;
							}
						case 3:
							{
								Console.ForegroundColor = ConsoleColor.Red;
								break;
							}
						case 4:
							{
								Console.ForegroundColor = ConsoleColor.Green;
								break;
							}
						case 5:
							{
								Console.ForegroundColor = ConsoleColor.Yellow;
								break;
							}
					}
					amp = false;
					hold = true;
				}
				if (!hold) Console.Write(message[i]);
			}
			Console.ForegroundColor = ConsoleColor.White;
		}

		/*				COLORS
		 *				
		 *				1 - White
		 *				2 - Blue
		 *				3 - Red
		 *				4 - Green
		 *				5 - Yellow
		 * */

		static void Main(string[] args)
		{
			string connetionString;
			MySqlConnection con;
			connetionString = @"Server=sql11.freesqldatabase.com,3306;Database=XXX;User Id=XXX;Password=XXX;";
			print("@5Attempting to connect to SQL...\n");
			con = new MySqlConnection(connetionString);
			try
			{
				con.Open();
				print("@4Successfully connected to SQL. Checking your license...");

				ManagementObject dsk = new ManagementObject(
					@"win32_logicaldisk.deviceid=""" + "C" + @":""");
				dsk.Get();
				string volumeSerial = dsk["VolumeSerialNumber"].ToString();
				var s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_OperatingSystem");
				var obj = s.Get().Cast<ManagementObject>().First();
				var id = obj["SerialNumber"].ToString();

				string query = "SELECT * FROM licenses";
				MySqlCommand cmd = new MySqlCommand(query, con);
				MySqlDataReader rdr = cmd.ExecuteReader();
				bool found = false;
				while (rdr.Read())
				{
					if (rdr.GetString(1).Equals(id + "-" + volumeSerial) && rdr.GetInt32(3) == 1)
					{
						print("@4  OK!\n");
						found = true;
						break;
					}
				}
				if (!found)
				{
					print("\n@3Unable to find your license!");
					Console.Read(); return;
				}
			}
			catch (Exception e)
			{
				print("\n@3" + e.Message);
				Console.Read();
				return;
			}
			Console.Clear();
			Console.Title = "f0X checker";
			do
			{
				print("@2Awaiting contract: ");
				contract = Console.ReadLine();
				_func();
			}
			while (!contract.Equals("0x0"));
		}
	}
}
