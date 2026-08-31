# Chrome Native Messaging Echo Demo

A minimal Linux example showing:

```text
Chrome extension popup
        |
        | chrome.runtime.sendNativeMessage()
        v
Chrome Native Messaging
        |
        | stdin/stdout pipe
        v
echo_host (C)
```

The C host does **not parse JSON**. It reads the Native Messaging frame from
`stdin` and writes exactly the same frame to `stdout`.

## Directory layout

```text
native-messaging-echo/
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
└── native_host/
    ├── echo_host.c
    ├── Makefile
    ├── install_host.sh
    ├── uninstall_host.sh
    └── com.example.native_echo.json.template
```

## 1. Build the C host

```bash
cd native-messaging-echo/native_host
make
```

This creates:

```text
native_host/echo_host
```

## 2. Load the Chrome extension

Open:

```text
chrome://extensions/
```

Then:

1. Enable **Developer mode**.
2. Click **Load unpacked**.
3. Select the `native-messaging-echo/extension` directory.
4. Copy the extension ID displayed by Chrome.

The ID looks similar to:

```text
abcdefghijklmnopabcdefghijklmnop
```

## 3. Register the Native Messaging Host

From `native_host/`:

```bash
./install_host.sh YOUR_EXTENSION_ID
```

For a user installation of Google Chrome on Linux, this creates:

```text
~/.config/google-chrome/NativeMessagingHosts/com.example.native_echo.json
```

The generated file looks like:

```json
{
  "name": "com.example.native_echo",
  "description": "Native Messaging Echo Host",
  "path": "/absolute/path/to/native-messaging-echo/native_host/echo_host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://YOUR_EXTENSION_ID/"
  ]
}
```

If the extension ID changes, run `install_host.sh` again with the new ID.

## 4. Run the demo

1. Click the extension icon in Chrome.
2. Type text into **Input**.
3. Click **Send to native host**.
4. The response appears under **Output**.

For example, the extension sends the JavaScript object:

```json
{
  "text": "Hello from Chrome"
}
```

Chrome serializes it to JSON and sends a Native Messaging frame to the
C application's stdin:

```text
+------------------------+--------------------------+
| uint32_t JSON length   | UTF-8 JSON bytes         |
| native byte order      |                          |
+------------------------+--------------------------+
```

`echo_host` writes the same length and JSON bytes to stdout. Chrome parses the
reply and `popup.js` displays it.

## Important stdout rule

The native program must not use stdout for debugging messages.

Wrong:

```c
printf("debug\n");
```

This corrupts the Native Messaging protocol.

Use stderr instead:

```c
fprintf(stderr, "debug\n");
```

## Why the C host loops

This demo uses `chrome.runtime.sendNativeMessage()`, for which Chrome starts a
native host process for a message and uses its first response.

The C program nevertheless loops after each response so the same binary can
also be used later with `chrome.runtime.connectNative()`, which maintains a
port and can exchange multiple messages with the same host process.

## Uninstall the host registration

```bash
cd native-messaging-echo/native_host
./uninstall_host.sh
```

## Chromium instead of Google Chrome

The Native Messaging manifest directory differs. For a per-user Chromium
installation it is typically:

```text
~/.config/chromium/NativeMessagingHosts/
```

The supplied installer targets Google Chrome.
