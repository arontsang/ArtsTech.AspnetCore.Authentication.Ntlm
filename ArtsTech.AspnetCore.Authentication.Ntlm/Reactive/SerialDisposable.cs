using System;
using System.Reactive.Disposables;

#nullable enable
namespace ArtsTech.AspnetCore.Authentication.Ntlm.Reactive
{
    internal class SerialDisposable<T> : IDisposable where T : IDisposable
    {
        private readonly SerialDisposable _serialDisposable = new();
        
        public T? Disposable
        {
            get => (T?)_serialDisposable.Disposable;
            set => _serialDisposable.Disposable = value;
        }

        public void Dispose()
        {
            _serialDisposable.Dispose();
        }
    }
}
