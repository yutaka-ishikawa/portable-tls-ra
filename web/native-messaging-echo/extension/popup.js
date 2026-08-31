const HOST_NAME = "com.example.native_echo";

const input = document.getElementById("input");
const output = document.getElementById("output");
const sendButton = document.getElementById("send");

async function sendToNativeHost() {
  sendButton.disabled = true;
  output.textContent = "Sending...";

  try {
    const request = {
      text: input.value
    };

    /*
     * Chrome serializes this object as JSON and sends:
     *
     *   [4-byte native-endian message length][UTF-8 JSON]
     *
     * to the native host's stdin.
     *
     * sendNativeMessage() starts a native host process for this message
     * and resolves with the first JSON message written by the host.
     */
    const response = await chrome.runtime.sendNativeMessage(
      HOST_NAME,
      request
    );

    output.textContent = JSON.stringify(response, null, 2);
  } catch (error) {
    output.textContent =
      "Native Messaging error:\n" +
      (error?.message ?? String(error));
  } finally {
    sendButton.disabled = false;
  }
}

sendButton.addEventListener("click", sendToNativeHost);

input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    sendToNativeHost();
  }
});
