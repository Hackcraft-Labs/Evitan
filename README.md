# Evitan

A Native Application Subsystem backdoor.

## Features

- Elevated Process / Thread Termination
- Token Session ID Swapping
- Process Memory Dumping

## Usage

Backdooring a system with Evitan requires a way to:
- Write a file to C:\Windows\System32.
- Modify the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute** or **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecuteNoPnpSync** registry keys.

## Inner Workings

Evitan's inner workings are described in its accompanying blog post which can be found [here](https://hackcraft.gr/blog).

## References / Prior Research
- [Pavel's NativeApps](https://github.com/zodiacon/NativeApps)
- [Pavel's SECArmy Village Grayhat 2020 Presentation](https://www.youtube.com/watch?v=EKBvLTuI2Mo)
- [Protexity's Going Native Blog Post](https://www.protexity.com/post/going-native-malicious-native-applications)

## Disclaimer

This code and the blog psot are provided only as a POC and are not expected to be production-grade, bug-free code. Please take this into consideration before utilizing Evitan. Moreover, the NativeRun application included in the Evitan project (utilized for easily running Native Applications for testing purposes) is borrowed from [Pavel's NativeApps project](https://github.com/zodiacon/NativeApps). It is not required for running Evitan and is only included to facilitate its testing (all credits regarding NativeRun go to the original author).