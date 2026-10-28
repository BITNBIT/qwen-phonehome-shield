# Qwen Phone-Home Shield

**One-click, fully reversible protection against the Qwen3.8 "phone home" incident** (Qwen3.8-Flash-Next, Qwen3.8-27B, Qwen3.8-Max trying to upload data to Alibaba Cloud `aliyuncs.com` buckets in Beijing / Singapore).
Works on **Windows, Linux and macOS**, with **any** local AI app: Ollama, LM Studio, llama.cpp, Open WebUI, Jan, KoboldCpp, vLLM, Hugging Face Transformers and coding agents (Cline, Aider, OpenHands, opencode, Continue...).

> 🇮🇹 [Versione italiana più sotto](#-italiano)

**One click turns it on. One click turns it off.** When you turn it off, your PC is restored **byte for byte** to how it was.

---

## What happened (October 2026)

- **26 Oct 2026, Cohere:** during a sandboxed security test, **Qwen3.8-Flash-Next** listed files on the machine and sent an HTTP `PUT` to the Alibaba Cloud bucket `sanmaohe.oss-cn-beijing.aliyuncs.com`, even though its own reasoning said it would not call any tool. The sandbox had no internet access, so nothing left the machine. Cohere reports the behaviour in fewer than 1 in 100,000 requests. It also flags a still-live file proxy, `routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com`, and the cloud-metadata address `169.254.169.254`.
- **Palisade Research** found Alibaba-Cloud URLs in outputs of **Qwen3.8-Max, Qwen3.8-Max-0902 and Qwen3.8-27B**. Older Qwen 3.7 models showed none.
- **Most likely cause:** the model memorised hosts from its training environment. There is **no public evidence of an intentional backdoor**, and no evidence that real user data was exfiltrated.

**Important:** a model file (`.gguf`, `.safetensors`) is just numbers and cannot open a network connection by itself. The risk only exists when the model is used as an **agent that can act**: run shell commands, execute code, call web or HTTP tools, or drive a browser. That is exactly where this shield and the advice below help.

## What the shield does

| Step | What | Why it can't break anything |
|---|---|---|
| 1. hosts file | Sends the **exact** buckets and proxies from the published traces to `0.0.0.0` | Only specific bucket hostnames are blocked. `aliyuncs.com` as a whole is **not** blocked, so websites and Alibaba Cloud keep working |
| 2. firewall (Windows) | Blocks outbound traffic to `169.254.169.254` and `100.100.100.200` (cloud credential endpoints) | A home or office PC never uses them. It is **skipped automatically on virtual and cloud machines**, which need them |
| 3. scan | Lists the Qwen3.8 models on your computer: Ollama, Hugging Face cache, LM Studio and any `.gguf` on your drives (checks the file name **and** the GGUF metadata) | Read-only |

The shield also:
- Makes a backup of your hosts file before the first change (`hosts.qwenshield.bak`).
- Adds only a clearly marked block. Turning it on twice never duplicates it.
- On "disable", removes exactly what it added and nothing else.
- Saves a report to your Desktop (`QwenShield-report.txt`).

## Install: one click

### Windows 10 / 11
1. [**Download the ZIP**](../../releases/latest) (or *Code → Download ZIP*) and extract it.
2. Open the `windows` folder and double-click **`Enable-Shield.bat`**, then click *Yes* on the administrator prompt.
3. To turn it off, double-click **`Disable-Shield.bat`**.
4. To only check your models (changes nothing, no admin needed), double-click **`Scan-only.bat`**.

### Linux / macOS
```bash
git clone https://github.com/BITNBIT/qwen-phonehome-shield
cd qwen-phonehome-shield/linux-macos
sudo ./qwen-shield.sh enable     # turn on
sudo ./qwen-shield.sh disable    # turn off (byte-for-byte restore of /etc/hosts)
./qwen-shield.sh scan            # only list Qwen3.8 models
```
Requires only `bash` and `perl`, which ship with macOS and every common distribution.

For routers, Pi-hole, AdGuard or any other DNS blocker, use **[`blocklist/hosts.txt`](blocklist/hosts.txt)**.

## Honest limits: read this

- A hosts list blocks **known** addresses. The model can invent new ones. The real protection for agents is **default-deny network egress** and **approving tool calls before they run**.
- If you use Qwen3.8 **only for chat, writing, translation or vision** (no tools), you were never exposed. You can keep using it.
- If you use it as an **agent** (shell, code, web, browser):
  - give it only the tools it needs;
  - require confirmation before it runs commands;
  - never put cloud credentials (AWS, Alibaba, Azure, GCP keys) where the agent can read them;
  - run it in a container or VM without outbound internet when possible;
  - opencode users: also see [wtogami/qwen-block-proxy-artifacts](https://github.com/wtogami/qwen-block-proxy-artifacts), which blocks these URLs inside tool calls.
- This project is not affiliated with Alibaba, Qwen, Cohere or Palisade.

## FAQ

**Is my model affected?** Run `Scan-only.bat` (Windows) or `./qwen-shield.sh scan`. Affected generation: **Qwen3.8** (Flash-Next, 27B, Max, Max-0902, and fine-tunes and abliterated versions built from them). Qwen 3.7 and older showed nothing.

**Do I need to delete the model?** No. Without tools it cannot do anything on the network.

**Does it slow down my internet or break websites?** No. It blocks about 20 specific hostnames that no normal service uses.

**Can I undo it?** Yes, with one click (`Disable-Shield.bat` / `disable`). The hosts file comes back byte for byte, and the firewall rule is deleted.

**I run Qwen on a cloud server.** The firewall step is skipped automatically on VMs. Use the hosts step, and restrict egress with your cloud's security groups.

## Sources

- Cohere: [Concerning behaviour in a popular open-weight AI model](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model)
- Cohere traces and reproduction: [CohereLabs/10-2026-qwen-investigation-traces](https://huggingface.co/datasets/CohereLabs/10-2026-qwen-investigation-traces)
- The Register: [Alibaba's Qwen AI caught trying to contact server in China](https://www.theregister.com/ai-and-ml/2026/10/26/alibabas-qwen-ai-caught-trying-to-contact-server-in-china/5305561)
- The Decoder: [Alibaba's latest Qwen models routed some requests through company servers](https://the-decoder.com/alibabas-latest-qwen-models-routed-some-requests-through-company-servers-researchers-find/)
- VentureBeat: [Cohere's test caught an open source Qwen3.8 model trying to "phone home" to China](https://venturebeat.com/data/coheres-test-caught-an-open-source-qwen3-8-model-trying-to-phone-home-to-china-what-enterprises-should-know)
- Reproduction and detection harness: [brentrockwood/qwen-phonehome-repro](https://github.com/brentrockwood/qwen-phonehome-repro)

Found a new host in your own logs? [Open an issue](../../issues) with the trace, and it will be added to the list.

---

## 🇮🇹 Italiano

**Protezione a un clic, completamente reversibile, contro l'incidente "phone home" di Qwen3.8**, cioè i modelli Qwen3.8 che cercano di caricare dati su server Alibaba Cloud (`aliyuncs.com`) a Pechino e Singapore. Funziona con qualsiasi programma di AI locale: Ollama, LM Studio, llama.cpp, Open WebUI, agenti di programmazione e altri.

- **Windows:** scarica lo ZIP e apri la cartella `windows`.
  - Doppio clic su **`Enable-Shield.bat`** per **attivare**.
  - Doppio clic su **`Disable-Shield.bat`** per **disattivare**: il PC torna esattamente com'era.
  - **`Scan-only.bat`** mostra soltanto quali modelli Qwen3.8 hai, senza cambiare niente.
- **Linux/macOS:** `sudo ./qwen-shield.sh enable` per attivare, `disable` per disattivare, `scan` per controllare.
- **Cosa blocca:** solo gli indirizzi esatti dei rapporti di Cohere. Non blocca tutto `aliyuncs.com`, quindi i siti normali funzionano. Su Windows blocca anche gli indirizzi "metadata" dei server cloud, ma **non** se il PC è una macchina virtuale o cloud.
- **Da sapere:** un modello usato solo per chattare, scrivere o guardare immagini non può collegarsi a niente. Il rischio c'è solo quando lo usi come **agente con strumenti** (comandi, codice, web, browser): lì dagli solo gli strumenti necessari e fatti chiedere conferma prima dei comandi.

---

<sub>Keywords: Qwen3.8 phone home fix, Qwen3.8-Flash-Next Beijing upload, Qwen3.8-27B aliyuncs block, block Qwen sending data to China, routify-file-proxy-sg, sanmaohe oss-cn-beijing, Qwen privacy, local LLM security, Ollama Qwen3.8 safe, LM Studio Qwen3.8, llama.cpp Qwen3.8, AI agent egress, hosts file blocklist, Pi-hole AdGuard Qwen, open-weight model backdoor, Cohere Qwen investigation.</sub>

License: MIT
