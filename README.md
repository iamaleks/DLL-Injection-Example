# DLL Injection Example

Example implementation of DLL Injection.

Related to blog post located at [https://posts.thinkbox.dev/malware-techniques-dll-injection/](https://posts.thinkbox.dev/malware-techniques-dll-injection/)

## Execution Instructions

1. Copy DLL Payload to `C:\`.

The `ReflectiveDLL.dll` file should be located under `C:\DLLPayload.dll`.

2. Ensure notepad.exe is running

The `DLLInjector.exe` is made to inject into a running instance of notepad.exe.

3. Execute `DLLInjector.exe`

Run `DLLInjector.exe` with administrator permissions.
