#r "/opt/dnlib/dnlib.dll"
using dnlib.DotNet;
System.Console.WriteLine("dnlib " + typeof(ModuleDefMD).Assembly.GetName().Version + " OK");
