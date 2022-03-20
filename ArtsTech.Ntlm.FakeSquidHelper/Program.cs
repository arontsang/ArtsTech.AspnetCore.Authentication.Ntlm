

using var stdin = new StreamReader(Console.OpenStandardInput());

while (true)
{
    var command = await stdin.ReadLineAsync();
    if (command == null) return 0;

    var commandParts = command.Split(' ', 2);

    switch (commandParts[0])
    {
        case "YR":
            Console.WriteLine("TT TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA=");
            continue;
        case "KK":
            Console.WriteLine("AF DOMAIN\\USER");
            continue;
        default:
            Console.WriteLine($"BH Unknown command type {commandParts[0]}");
            return 1;
    }
}