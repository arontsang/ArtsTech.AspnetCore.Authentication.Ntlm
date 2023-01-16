using System.Diagnostics;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.Sample;

public class WinBindService : BackgroundService
{
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		// Since we are running in a docker container
		// winbindd won't autostart

		using var winbind = Process.Start(new ProcessStartInfo("/bin/sh", "./run-samba.sh") { RedirectStandardOutput = true });
		
		try
		{
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
		}
		finally
		{
			winbind.Close();
		}
	}
}