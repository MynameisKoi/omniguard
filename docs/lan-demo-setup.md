# LAN demo setup

The victim laptop points at the analyst laptop by IP address. That IP changes
every time you join a different WiFi, so re-do this whenever the network changes.

## 1. Find the analyst laptop's IP

On the **analyst** laptop (the one running the app):

- Mac:
  ```
  ipconfig getifaddr en0
  ```
  (if blank, run `ifconfig | grep "inet "` and take the `192.168.x.x` one)

- Windows (PowerShell):
  ```
  Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} | Select-Object IPAddress, InterfaceAlias
  ```
  Use the one whose InterfaceAlias is `Wi-Fi`.

Write it down, e.g. `192.168.1.234`. This is the ANALYST IP.

## 2. Start the app on the analyst laptop

The backend and engine must listen on all interfaces, not just localhost:

```
cd backend && source venv/bin/activate && uvicorn main:app --host 0.0.0.0 --port 8000
cd verifyeye-ingress && source venv/bin/activate && uvicorn service:app --host 0.0.0.0 --port 8100
cd spectrac2-engine && source venv/bin/activate && uvicorn service.main:app --host 0.0.0.0 --port 8001
```

Also start the dashboard, fake sites, Mongo, Neo4j and Ollama as usual.

## 3. Point the victim laptop at the analyst IP

On the **victim** laptop, change the ANALYST IP in two files:

- `verifyeye-ingress/extension/background.js` (top of the file):
  ```
  const CORE   = "http://192.168.1.234:8000";
  const VERIFY = "http://192.168.1.234:8100";
  ```
  Then reload the extension: `chrome://extensions` -> reload button on the card.

- `demo/beacon_sim.py` (top of the file):
  ```
  ANALYST_IP = "192.168.1.234"
  ```

Use the new IP from step 1. Do not commit these lines — they are per-machine.

## 4. Host name

Each victim laptop sets its own name, the same string in both files:

- `verifyeye-ingress/extension/content.js` -> `host: "lenovo-10"`
- `demo/beacon_sim.py` -> `HOST = "lenovo-10"`

They must match exactly (same spelling and case) or the two alerts will not
correlate to the same machine.

## 5. Containment agent (for real isolate/release)

To let the analyst actually cut a host off the network, run the containment
agent on the victim laptop. It needs admin, because it changes routes.

- Set the same `ANALYST_IP` and `HOST` at the top of `demo/containment_agent.py`
  (the `HOST` must match the extension/beacon host exactly).
- Run it as admin:
  - Windows (open PowerShell as Administrator):
    ```
    python demo\containment_agent.py
    ```
  - Mac/Linux:
    ```
    sudo python3 demo/containment_agent.py
    ```

Now on the analyst dashboard, open an alert for that host and use
Isolate / Release. The victim really loses internet on isolate and gets it back
on release. It also auto-releases after a timeout and on closing the agent, so
the machine can't get stuck offline. The SOC must be on the SAME subnet as the
victim (it is, on the demo WiFi) so the control channel survives isolation.

## 6. Check they can reach each other

From the victim laptop:

```
ping 192.168.1.234
```

If it replies, you are good. If not: both laptops must be on the same WiFi, and
the analyst laptop's firewall must allow incoming connections.
