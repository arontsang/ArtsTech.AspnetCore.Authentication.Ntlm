using System.Diagnostics;
using System.Reactive.Concurrency;
using System.Reactive.Disposables;

namespace ArtsTech.AspnetCore.Authentication.Ntlm.Sample;

public class WinBindService : IHostedService
{
	private readonly SerialDisposable _runSamba = new();
	
	public async Task StartAsync(CancellationToken cancellationToken)
	{
		using var winbind = Process.Start(new ProcessStartInfo("/bin/sh", "./run-samba.sh") { RedirectStandardOutput = true })!;
		await winbind.WaitForExitAsync(cancellationToken);

		_runSamba.Disposable = TaskPoolScheduler.Default.ScheduleAsync(default(object), async (_, _, stoppingToken) =>
		{
			using var samba = Process.Start(new ProcessStartInfo("samba", "-F --no-process-group") { RedirectStandardOutput = true })!;
			try
			{
				await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
			}
			finally
			{
				samba.Close();
			}
		});
	}

	public Task StopAsync(CancellationToken cancellationToken)
	{
		_runSamba.Dispose();
		return Task.CompletedTask;
	}

}