using System;
using System.Diagnostics;

class Program {
    static void Main() {
        string cmd = Console.ReadLine();
        Process.Start(cmd); // 🚨 flagged: highlights `cmd`
    }
}
