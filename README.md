# CTF Flag Catcher

A Burp Suite extension that automatically detects and highlights CTF flags in HTTP responses.

## Features

- Passively monitors all HTTP responses through Burp Suite
- Detects flags matching the patterns of popular CTF platforms
- Highlights matching requests **red** in the Proxy/HTTP history
- Adds a comment to the request with the captured flag(s)
- Prints found flags to the Burp extension output console

## Requirements

- [Burp Suite](https://portswigger.net/burp) (Community or Pro)
- [Jython Standalone JAR](https://www.jython.org/download) (2.7.x recommended)

## Installation

1. Download the [Jython standalone JAR](https://www.jython.org/download) and configure it in Burp:
   - Go to **Extensions > Options > Python Environment**
   - Set the path to your `jython-standalone-x.x.x.jar`

2. Load the extension:
   - Go to **Extensions > Add**
   - Set **Extension type** to `Python`
   - Select `flag_catcher.py`
   - Click **Next**

## Usage

Once loaded, the extension runs automatically in the background. Any HTTP response containing a supported flag will be:

- Highlighted red in Burp's HTTP history
- Annotated with a comment showing the flag value
- Printed to the **Extension output** tab

## Flag Format

Targets flags matching the regex pattern:

```
bug\{[^}]+\}
```

Example: `bug{th1s_1s_4_fl4g}`

## License

MIT
